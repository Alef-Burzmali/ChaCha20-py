import itertools

BITS_32b = 32
BITMASK_32b = (1<<BITS_32b) - 1
CHACHA20_BLOCK_LEN = 64
POLY1305_BLOCK_LEN = 16
BITMASK_128b = (1<<128) - 1

class DecryptionError(ValueError):
    pass

def chunks(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

def bytes_xor(a,b):
    return bytes(x^y for x,y in zip(a,b) if x is not None and y is not None)

def add(a, b):
    return (a+b) & BITMASK_32b

def rotl(n, shift):
    return ((n << shift) | (n >> (BITS_32b - shift))) & BITMASK_32b

def pad16(x_len : int):
    if x_len % 16:
        return b"\x00" * (16 - (x_len%16))
    else:
        return b""

def quarterround(a,b,c,d):
    a = add(a,b); d = rotl(a^d, 16)
    c = add(c,d); b = rotl(b^c, 12)
    a = add(a,b); d = rotl(a^d,  8)
    c = add(c,d); b = rotl(b^c,  7)
    return (a,b,c,d)

def inner_block(x0, x1, x2, x3,
        x4, x5, x6, x7,
        x8, x9, x10, x11,
        x12, x13, x14, x15):

    for _ in range(10):
        x0,x4,x8,x12  = quarterround(x0,x4,x8,x12)
        x1,x5,x9,x13  = quarterround(x1,x5,x9,x13)
        x2,x6,x10,x14 = quarterround(x2,x6,x10,x14)
        x3,x7,x11,x15 = quarterround(x3,x7,x11,x15)

        x0,x5,x10,x15 = quarterround(x0,x5,x10,x15)
        x1,x6,x11,x12 = quarterround(x1,x6,x11,x12)
        x2,x7,x8,x13  = quarterround(x2,x7,x8,x13)
        x3,x4,x9,x14  = quarterround(x3,x4,x9,x14)

    return (
        x0, x1, x2, x3,
        x4, x5, x6, x7,
        x8, x9, x10, x11,
        x12, x13, x14, x15
        )


def chacha20_block(parsed_key, parsed_nonce, block_count, *, debug=False):
    initial_state = (
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            *parsed_key,
            block_count,
            *parsed_nonce
        )
    state = inner_block(*initial_state)
    final_state = tuple(add(a,b) for a,b in zip(state,initial_state))

    if debug:
        return (initial_state,state,final_state)
    else:
        return b''.join(c.to_bytes(4, "little") for c in final_state)


def chacha20_encrypt_iter(key : bytes, nonce : bytes, message : iter, initial_counter : int = 0, *, debug=False):
    assert len(key) == 32, f"Key must be a 256 bits (32 bytes) bytestring, got {len(key)} bytes"
    assert len(nonce) == 12, f"Nonce must be a 96 bits (12 bytes) bytestring, got {len(nonce)} bytes"
    assert (type(initial_counter) == int) and (initial_counter >= 0), f"Initial counter must be a positive or null integer, got {initial_counter}"

    message = iter(message)
    parsed_key = tuple(int.from_bytes(key[i:i+4], "little") for i in range(0,32,4))
    parsed_nonce = tuple(int.from_bytes(nonce[i:i+4], "little") for i in range(0,12,4))

    if debug:
        for k, block in enumerate(chunks(message, CHACHA20_BLOCK_LEN)):
            i,m,f = chacha20_block(parsed_key, parsed_nonce, initial_counter+k, debug=True)
            encrypted_block = bytes_xor(block, chacha20_block(parsed_key, parsed_nonce, initial_counter+k))
            yield (i,m,f,encrypted_block) 
    else:
        for k, block in enumerate(chunks(message, CHACHA20_BLOCK_LEN)):
            yield bytes_xor(block, chacha20_block(parsed_key, parsed_nonce, initial_counter+k))

def chacha20_encrypt(key : bytes, nonce : bytes, message : bytes, initial_counter : int = 0, *, debug=False):
    if debug:
        results = []
        output = b""
        for x in chacha20_encrypt_iter(key, nonce, message, initial_counter, debug=True):
            results += [x]
            output += x[3]
        return results, output
    else:
        return b''.join(chacha20_encrypt_iter(key, nonce, message, initial_counter))

def poly1305(key : bytes, message : bytes, *, debug=False):
    assert len(key) == 32, f"Key must be a 256 bits (32 bytes) bytestring, got {len(key)} bytes"

    r, s = int.from_bytes(key[:16], 'little'), int.from_bytes(key[16:], 'little')
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    p = 0x3fffffffffffffffffffffffffffffffb
    accu = 0
    for k, block in enumerate(chunks(message, POLY1305_BLOCK_LEN)):
        block_str = bytes([c for c in block if c is not None] + [1])

        accu += int.from_bytes(block_str, 'little')
        accu *= r
        accu = accu % p

    accu += s
    accu = accu & BITMASK_128b
    auth = accu.to_bytes(16, "little")

    if debug:
        return r,s,auth
    else:
        return auth

def poly1305_key_gen(master_key : bytes, nonce : bytes):
    assert len(master_key) == 32, f"Key must be a 256 bits (32 bytes) bytestring, got {len(key)} bytes"
    assert len(nonce) == 12, f"Nonce must be a 96 bits (12 bytes) bytestring, got {len(nonce)} bytes"

    parsed_key = tuple(int.from_bytes(master_key[i:i+4], "little") for i in range(0,32,4))
    parsed_nonce = tuple(int.from_bytes(nonce[i:i+4], "little") for i in range(0,12,4))

    block = chacha20_block(parsed_key, parsed_nonce, 0)
    return block[0:32]

def aead_compute_tag(poly1305_key : bytes, ciphertext : bytes, aad : bytes, *, debug=False):
    aad_len = len(aad)
    ciphertext_len = len(ciphertext)
    authenticated_message = (
        aad + pad16(aad_len) +
        ciphertext + pad16(ciphertext_len) +
        aad_len.to_bytes(8, 'little') + 
        ciphertext_len.to_bytes(8, 'little')
        )

    authentication_tag = poly1305(poly1305_key, authenticated_message)
    if debug:
        return authenticated_message, authentication_tag
    else:
        return authentication_tag

def aead_chacha20_poly1305_encrypt(key : bytes, nonce : bytes, plaintext : bytes = b"", aad : bytes = b""):
    assert len(key) == 32, f"Key must be a 256 bits (32 bytes) bytestring, got {len(key)} bytes"
    assert len(nonce) == 12, f"Nonce must be a 96 bits (12 bytes) bytestring, got {len(nonce)} bytes"
    
    poly1305_key = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, nonce, plaintext, initial_counter=1)
    authentication_tag = aead_compute_tag(poly1305_key, ciphertext, aad)
    return ciphertext + authentication_tag

def tag_validate(tag1 : bytes, tag2 : bytes):
    assert len(tag1) == 16, "Authentication tags are 16-byte long"
    assert len(tag2) == 16, "Authentication tags are 16-byte long"

    accu = 0
    for a,b in zip(tag1, tag2):
        accu |= a^b
    return accu == 0

def aead_chacha20_poly1305_decrypt(key : bytes, nonce : bytes, ciphertext : bytes = b"", aad : bytes = b""):
    assert len(key) == 32, f"Key must be a 256 bits (32 bytes) bytestring, got {len(key)} bytes"
    assert len(nonce) == 12, f"Nonce must be a 96 bits (12 bytes) bytestring, got {len(nonce)} bytes"
    assert len(ciphertext) >= 16, f"Ciphertext must be at least 128 bits (16 bytes) bytestring, got {len(ciphertext)} bytes"
    
    ciphertext, provided_tag = ciphertext[:-16], ciphertext[-16:]

    poly1305_key = poly1305_key_gen(key, nonce)
    plaintext = chacha20_encrypt(key, nonce, ciphertext, initial_counter=1)
    computed_tag = aead_compute_tag(poly1305_key, ciphertext, aad)

    if not tag_validate(computed_tag, provided_tag):
        raise DecryptionError()
    return plaintext

if __name__ == "__main__":
    plaintext = b"\x00" * (1<<(20))
    key = b"\x00" * 32
    nonce = b"\x00" * 12

    ciphertext = aead_chacha20_poly1305_encrypt(key, nonce, plaintext)
    decrypted = aead_chacha20_poly1305_decrypt(key, nonce, ciphertext)
    assert decrypted == plaintext