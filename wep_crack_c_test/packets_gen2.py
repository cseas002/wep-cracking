import csv
import random

WEAK_IVS = True
PACKETS_MULT_AMT = 1000


def rc4(key, plaintext_length):
    """Simplified RC4 implementation"""
    # Key Scheduling Algorithm (KSA)
    key_length = len(key)
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    keystream = []
    for _ in range(plaintext_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        keystream.append(S[(S[i] + S[j]) % 256])

    return keystream


def generate_weak_ivs_and_ciphertexts(key, num_iv=256):
    """Generate weak IVs and corresponding keystream"""
    weak_ivs = []
    ciphertexts = []

    for key_byte in range(len(key)):  # There are 5 bytes in the key
        for x in range(num_iv):
            for j in range(PACKETS_MULT_AMT):
                if WEAK_IVS:
                    iv = (key_byte + 3, 255, x)
                else:
                    iv = (random.randint(0, 255), random.randint(0, 255),
                          random.randint(0, 255))
                weak_ivs.append(iv)

                # Generate a key stream of 10 bytes
                keystream = rc4(key, 10)
                ciphertext = [0xAA ^ keystream[0]]
                # Generate the ciphertext, which is a list of random bytes XOR'd with the keystream
                for i in range(9):
                    ciphertext.append(random.randint(0, 255) ^ keystream[i + 1])
                ciphertexts.append(ciphertext)

    return weak_ivs, ciphertexts


def save_to_csv(weak_ivs, ciphertexts, filename='packets.csv'):
    """Save weak IVs to a CSV file"""
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # writer.writerow(["IV", "Ciphertext"])
        for i in range(len(weak_ivs)):
            row = []
            for j in range(3):
                row.append(weak_ivs[i][j])
            for j in range(10):
                row.append(ciphertexts[i][j])
            writer.writerow(row)


def main():
    # Set default key as hexadecimal value 0xAAAA
    default_key_hex = '0xAF1423'

    # key_input = input(f"Enter the key in hexadecimal format (default: {default_key_hex}): ") or default_key_hex
    key_input = default_key_hex
    key_input = key_input.replace("0x", "")  # Remove '0x' if present
    key = bytes.fromhex(key_input)  # Convert hex string to bytes

    weak_ivs, ciphertexts = generate_weak_ivs_and_ciphertexts(key)
    save_to_csv(weak_ivs, ciphertexts)
    print(f"Saved weak IVs to 'packets.csv' using key: {key.hex()}")


if __name__ == "__main__":
    main()
