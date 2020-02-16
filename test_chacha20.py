from chacha20 import *

def hex2state(string):
    byte_str = bytes.fromhex(string.replace(':',''))
    return tuple(int.from_bytes(byte_str[i:i+4], "little") for i in range(0,len(byte_str),4))

def repr_state(state):
    s = "\n"
    for j in range(0,4):
        s += f"\t{state[j*4+0]:08x}  {state[j*4+1]:08x}  {state[j*4+2]:08x}  {state[j*4+3]:08x}\n"
    return s

def test_add():
    for (a,b,e) in [
            (1,2,3),
            (45,78,123),
            (7, 14, 21),
            (BITMASK_32b, BITMASK_32b, BITMASK_32b-1),
            (1<<BITS_32b, 0, 0)
        ]:
        computed = add(a, b)
        expected = e
        assert computed == expected, f"Addition: add({a}, {b}) [{computed}] != {expected}"

def test_rotl():
    for i in range(0, 31):
        computed = rotl(1, i)
        expected = (1<<i)
        assert computed == expected, f"Powers of 2: rotl(1, {i}) [{computed}] != 1<<{i} [{expected}]"

    for n in [0,1,5,147,12]:
        computed = rotl(n, BITS_32b)
        expected = n
        assert computed == expected, f"Rot32: rotl({n}, {BITS_32b}) [{computed}] != {n} [{expected}]"

    for (n,i,e) in [(3,1,6), (12,5,384), ((1<<BITS_32b) - 1, 12, (1<<BITS_32b) - 1)]:
        computed = rotl(n, i)
        expected = e
        assert computed == expected, f"Known values: rotl({n}, {i}) [{computed}] != {expected}"

def test_quarterround():
    initial =  (0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)
    expected = (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
    computed = quarterround(*initial)

    assert computed == expected, (
        "Quarter round test vector:\n"
        f"quarterround({initial[0]:08x}, {initial[1]:08x}, {initial[2]:08x}, {initial[3]:08x}) := "
        f"({computed[0]:08x}, {computed[1]:08x}, {computed[2]:08x}, {computed[3]:08x}) != "
        f"({expected[0]:08x}, {expected[1]:08x}, {expected[2]:08x}, {expected[3]:08x})"
        )

    initial_state = (
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
    )
    expected_state = (
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    )
    initial = initial_state[2],initial_state[7],initial_state[8],initial_state[13]
    computed = quarterround(*initial)
    expected = expected_state[2],expected_state[7],expected_state[8],expected_state[13]
    assert computed == expected, (
        "Quarter round test state:\n"
        f"quarterround({initial[0]:08x}, {initial[1]:08x}, {initial[2]:08x}, {initial[3]:08x}) := "
        f"({computed[0]:08x}, {computed[1]:08x}, {computed[2]:08x}, {computed[3]:08x}) != "
        f"({expected[0]:08x}, {expected[1]:08x}, {expected[2]:08x}, {expected[3]:08x})"
        )

def test_chacha20_block():
    key = hex2state("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
    nonce = hex2state("00:00:00:09:00:00:00:4a:00:00:00:00")
    block_count = 1

    initial_state, intermediate_state, final_state = chacha20_block(key, nonce, block_count, debug=True)
    keystream = chacha20_block(key, nonce, block_count, debug=False)

    expected_initial = (
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        )
    expected_intermediate = (
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
        0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
        0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
        0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
        )
    expected_final = (
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        )
    expected_keystream = bytes.fromhex((
        "10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4"
        "c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e"
        "d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2"
        "b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e"
        ).replace(' ','')
    )

    assert initial_state == expected_initial, (
        "Initial states differ:"
        f"{repr_state(initial_state)}  != {repr_state(expected_initial)}"
        )
    assert intermediate_state == expected_intermediate, (
        "Shuffled states differ:"
        f"{repr_state(intermediate_state)}  != {repr_state(expected_intermediate)}"
        )
    assert final_state == expected_final, (
        "Final states differ:"
        f"{repr_state(final_state)}  != {repr_state(expected_final)}"
        )
    assert keystream == expected_keystream, (
        "Keystream differs: chacha20_block() := \n"
        f"{keystream.hex()}\n  !=\n{expected_keystream.hex()}"
        )

def test_chacha20_encrypt():
    key = bytes.fromhex("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".replace(":",""))
    nonce = bytes.fromhex("00:00:00:00:00:00:00:4a:00:00:00:00".replace(":",""))
    block_count = 1

    plaintext = bytes.fromhex((
        "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c"
        "65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"
        "73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"
        "6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"
        "6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"
        "74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"
        "63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"
        "74 2e"
        ).replace(' ',''))
    blocks, ciphertext = chacha20_encrypt(key, nonce, plaintext, initial_counter=block_count, debug=True)

    expected_keystream = bytes.fromhex((
        "22:4f:51:f3:40:1b:d9:e1:2f:de:27:6f:b8:63:1d:ed:8c:13:1f:82:3d:2c:06"
        "e2:7e:4f:ca:ec:9e:f3:cf:78:8a:3b:0a:a3:72:60:0a:92:b5:79:74:cd:ed:2b"
        "93:34:79:4c:ba:40:c6:3e:34:cd:ea:21:2c:4c:f0:7d:41:b7:69:a6:74:9f:3f"
        "63:0f:41:22:ca:fe:28:ec:4d:c4:7e:26:d4:34:6d:70:b9:8c:73:f3:e9:c5:3a"
        "c4:0c:59:45:39:8b:6e:da:1a:83:2c:89:c1:67:ea:cd:90:1d:7e:2b:f3:63"
        ).replace(':',''))
    expected_ciphertext = bytes.fromhex((
        "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81"
        "e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b"
        "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57"
        "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8"
        "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e"
        "52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36"
        "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42"
        "87 4d"
        ).replace(' ',''))

    expected_1st_initial = (
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x00000000, 0x4a000000, 0x00000000,
    )
    expected_2nd_initial = (
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000002, 0x00000000, 0x4a000000, 0x00000000,
    )
    expected_1st_final = (
        0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
        0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
        0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
        0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0,
    )
    expected_2nd_final = (
        0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
        0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
        0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
        0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139,
    )

    assert blocks[0][0] == expected_1st_initial, (
        "1st block initial states differ:"
        f"{repr_state(blocks[0][0])}  !={repr_state(expected_1st_initial)}"
        )
    assert blocks[1][0] == expected_2nd_initial, (
        "2nd block initial states differ:"
        f"{repr_state(blocks[1][0])}  !={repr_state(expected_2nd_initial)}"
        )
    assert blocks[0][2] == expected_1st_final, (
        "1st block final states differ:"
        f"{repr_state(blocks[0][2])}  !={repr_state(expected_1st_final)}"
        )
    assert blocks[1][2] == expected_2nd_final, (
        "2nd block final states differ:"
        f"{repr_state(blocks[1][2])}  !={repr_state(expected_2nd_final)}"
        )

    assert ciphertext == expected_ciphertext, (
        "Ciphertext differs: chacha20_encrypt() := \n"
        f"{ciphertext.hex()}\n  !=\n{expected_ciphertext.hex()}"
        )

    keystream = chacha20_encrypt(key, nonce, b'\x00'*len(plaintext), initial_counter=block_count)
    assert keystream == expected_keystream, (
        "Keystream differs: chacha20_encrypt() := \n"
        f"{keystream.hex()}\n  !=\n{expected_keystream.hex()}"
        )


def test_poly1305():
    key = bytes.fromhex("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b".replace(":",""))
    message = bytes.fromhex((
        "43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f"
        "72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f"
        "75 70"
        ).replace(' ',''))

    r,s, auth = poly1305(key, message, debug=True)

    expected_r = 0x806d5400e52447c036d555408bed685
    expected_s = 0x1bf54941aff6bf4afdb20dfb8a800301
    expected_auth = bytes.fromhex("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9".replace(":",""))

    assert r == expected_r, f"Key r differs: {r:16x} != {expected_r:16x}"
    assert s == expected_s, f"Key s differs: {s:16x} != {expected_s:16x}"

    assert auth == expected_auth, (
        f"Authentication tag differs:\n{auth.hex()}\n  !=\n{expected_auth.hex()}"
        )

def test_poly1305_key_gen():
    integrity_key = bytes.fromhex((
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
        ).replace(' ',''))
    nonce = bytes.fromhex("00 00 00 00 00 01 02 03 04 05 06 07".replace(' ',''))
    expected_poly1305_key = bytes.fromhex((
        "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71"
        "a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46"
        ).replace(' ',''))

    poly1305_key = poly1305_key_gen(integrity_key, nonce)

    assert poly1305_key == expected_poly1305_key, (
        f"Generated keys differ:\n{poly1305_key.hex()}\n  !=\n{expected_poly1305_key.hex()}"
        )

def test_pad16():
    for i, expected in [
            ( 0, b""),
            ( 1, b"\x00"*15),
            ( 2, b"\x00"*14),
            ( 3, b"\x00"*13),
            ( 4, b"\x00"*12),
            ( 5, b"\x00"*11),
            ( 6, b"\x00"*10),
            ( 7, b"\x00"* 9),
            ( 8, b"\x00"* 8),
            ( 9, b"\x00"* 7),
            (10, b"\x00"* 6),
            (11, b"\x00"* 5),
            (12, b"\x00"* 4),
            (13, b"\x00"* 3),
            (14, b"\x00"* 2),
            (15, b"\x00"* 1),
            (16, b""),
            (17, b"\x00"*15),
            (18, b"\x00"*14),
        ]:
    
        padding1 = pad16(i)
        padding2 = pad16(i+64)
        assert padding1 == expected, f"For input {i}: expected {expected.hex()} (len={len(expected)}), got {padding1.hex()} (len={len(padding1)})"
        assert padding2 == expected, f"For input {i+64}: expected {expected.hex()} (len={len(expected)}), got {padding2.hex()} (len={len(padding2)})"

def test_aead_compute_tag():
    aad = bytes.fromhex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7".replace(' ',''))
    key = bytes.fromhex((
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
        ).replace(' ',''))
    iv = bytes.fromhex("40 41 42 43 44 45 46 47".replace(' ',''))
    fixed_part = bytes.fromhex("07 00 00 00".replace(' ',''))
    nonce = fixed_part + iv
    ciphertext = bytes.fromhex((
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16"
        ).replace(' ',''))

    expected_poly1305_key = bytes.fromhex((
        "7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84"
        "0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff"
        ).replace(' ',''))
    poly1305_key = poly1305_key_gen(key, nonce)

    assert poly1305_key == expected_poly1305_key, (
        f"Generated keys differ:\n{poly1305_key.hex()}\n  !=\n{expected_poly1305_key.hex()}"
        )

    expected_tag = bytes.fromhex("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91".replace(':',''))
    expected_authenticated_message = bytes.fromhex((
        "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7 00 00 00 00"
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "0c 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00"
        ).replace(' ',''))

    computed_message, computed_tag = aead_compute_tag(poly1305_key, ciphertext, aad, debug=True)

    assert computed_message == expected_authenticated_message, (
        f"Authenticated message differs:\n"
        f"{computed_message.hex()}\n  !=\n{expected_authenticated_message.hex()}"
        )
    assert computed_tag == expected_tag, f"Tag differs:\n{computed_tag.hex()}\n  !=\n{expected_tag.hex()}"


def test_aead_chacha20_poly1305_encrypt_and_decrypt():
    plaintext = bytes.fromhex((
        "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c"
        "65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"
        "73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"
        "6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"
        "6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"
        "74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"
        "63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"
        "74 2e"
        ).replace(' ',''))
    aad = bytes.fromhex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7".replace(' ',''))
    key = bytes.fromhex((
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
        ).replace(' ',''))
    iv = bytes.fromhex("40 41 42 43 44 45 46 47".replace(' ',''))
    fixed_part = bytes.fromhex("07 00 00 00".replace(' ',''))
    nonce = fixed_part + iv

    expected_ciphertext = bytes.fromhex((
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16"
        ).replace(' ',''))
    expected_tag = bytes.fromhex("1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91".replace(':',''))
    expected_result = expected_ciphertext + expected_tag

    computed_result = aead_chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    computed_ciphertext, computed_tag = computed_result[:-16], computed_result[-16:]

    assert computed_ciphertext == expected_ciphertext, f"AEAD ciphertext differs:\n{computed_ciphertext.hex()}\n  !=\n{expected_ciphertext.hex()}"
    assert computed_tag == expected_tag, f"AEAD tag differs:\n{computed_tag.hex()}\n  !=\n{expected_tag.hex()}"
    assert computed_result == expected_result, f"AEAD encryption differs:\n{computed_result.hex()}\n  !=\n{expected_result.hex()}"

    decrypted_plaintext = aead_chacha20_poly1305_decrypt(key, nonce, computed_result, aad)
    assert decrypted_plaintext == plaintext, f"AEAD plaintext differs:\n{decrypted_plaintext.hex()}\n  !=\n{plaintext.hex()}"

def test_aead_chacha20_poly1305_decrypt():
    key = bytes.fromhex((
        "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"
        "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
        ).replace(' ',''))

    ciphertext = bytes.fromhex((
        "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd"
        "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2"
        "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0"
        "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf"
        "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81"
        "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55"
        "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38"
        "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4"
        "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9"
        "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e"
        "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a"
        "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a"
        "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e"
        "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10"
        "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30"
        "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29"
        "a6 ad 5c b4 02 2b 02 70 9b                     "
        ).replace(' ',''))

    nonce = bytes.fromhex((
        "00 00 00 00 01 02 03 04 05 06 07 08            "
        ).replace(' ',''))

    aad = bytes.fromhex((
        "f3 33 88 86 00 00 00 00 00 00 4e 91            "
        ).replace(' ',''))

    received_tag = bytes.fromhex((
        "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38"
        ).replace(' ',''))

    expected_plaintext = bytes.fromhex((
        "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20"
        "61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65"
        "6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20"
        "6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d"
        "6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65"
        "20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63"
        "65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64"
        "20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65"
        "6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e"
        "20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72"
        "69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65"
        "72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72"
        "65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61"
        "6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65"
        "6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20"
        "2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67"
        "72 65 73 73 2e 2f e2 80 9d                     "
        ).replace(' ',''))

    decrypted_plaintext = aead_chacha20_poly1305_decrypt(key, nonce, ciphertext + received_tag, aad)
    assert decrypted_plaintext == expected_plaintext, f"AEAD plaintext differs:\n{decrypted_plaintext.hex()}\n  !=\n{expected_plaintext.hex()}"

    wrong_tag = bytes.fromhex((
        "ef ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38"
        ).replace(' ',''))

    try:
        aead_chacha20_poly1305_decrypt(key, nonce, ciphertext + wrong_tag, aad)
    except DecryptionError:
        pass
    else:
        assert False, "AEAD decryption succeeded with an invalid tag"

    wrong_aad = aad + b"\x00"
    try:
        aead_chacha20_poly1305_decrypt(key, nonce, ciphertext + received_tag, wrong_aad)
    except DecryptionError:
        pass
    else:
        assert False, "AEAD decryption succeeded with an invalid AAD"

    wrong_ciphertext = ciphertext.replace(b"\x5c", b"\x5d")
    try:
        aead_chacha20_poly1305_decrypt(key, nonce, wrong_ciphertext + received_tag, aad)
    except DecryptionError:
       pass
    else:
        assert False, "AEAD decryption succeeded with an invalid ciphertext"


if __name__ == "__main__":
    test_rotl()
    test_add()
    test_quarterround()
    test_chacha20_block()
    test_chacha20_encrypt()
    test_poly1305()
    test_poly1305_key_gen()
    test_pad16()
    test_aead_compute_tag()
    test_aead_chacha20_poly1305_encrypt_and_decrypt()
    test_aead_chacha20_poly1305_decrypt()