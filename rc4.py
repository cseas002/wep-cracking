# Helper function, which swaps two values in the box.
def swapValueByIndex(box, i, j):
    temp = box[i]
    box[i] = box[j]
    box[j] = temp


# Initialize S-box.
def initSBox(box):
    for i in range(256):
        box[i] = i


# Key schedule Algorithm (KSA) for key whose value is in unicode or bytes.
def ksa(key, box):
    j = 0
    key_length = len(key)

    for i in range(256):
        j = (j + box[i] + key[i % key_length]) % 256
        swapValueByIndex(box, i, j)


def encrypt_decrypt_payload(payload, key):
    rc4_box = [0] * 256
    initSBox(rc4_box)
    ksa(key, rc4_box)  # Initialize RC4 key schedule
    keystream = prga(rc4_box)

    # Decrypt the payload
    decrypted_payload = bytearray()
    for byte in payload:
        decrypted_byte = byte ^ next(keystream)  # XOR with keystream
        decrypted_payload.append(decrypted_byte)
    return decrypted_payload


# KSA for key whose value is int
def ksaInt(key, box):
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) % 256
        swapValueByIndex(box, i, j)


def prga(box):
    """Pseudo-Random Generation Algorithm for generating keystream."""
    i = 0
    j = 0

    while True:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        swapValueByIndex(box, i, j)
        yield box[(box[i] + box[j]) % 256]
