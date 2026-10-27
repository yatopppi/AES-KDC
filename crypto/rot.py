from aes import round_key, bytes_to_matrix, aes

plaintext = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

tests = [
    (
        "000102030405060708090a0b0c0d0e0f",
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    ),
    (
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "dda97ca4864cdfe06eaf70a0ec0d7191"
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089"
    )
]

for key_hex, expected_hex in tests:
    key = bytes.fromhex(key_hex)
    result = aes(plaintext, key)

    assert result.hex() == expected_hex
    print(f"AES-{len(key)*8}: PASS")