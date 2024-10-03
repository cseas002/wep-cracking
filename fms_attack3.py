import pandas as pd
from collections import Counter


# RC4 Key Scheduling Algorithm (KSA)
def ksa(key):
    n = 256
    S = list(range(n))
    j = 0

    for i in range(n):
        j = (j + S[i] + key[i % len(key)]) % n
        S[i], S[j] = S[j], S[i]  # Swap

    return S


# Pseudo-Random Generation Algorithm (PRGA)
def prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        K = S[(S[i] + S[j]) % 256]
        yield K  # Generate the next byte of keystream


# Load weak IVs and ciphertexts from a CSV file
def load_ivs_from_csv(file_path):
    df = pd.read_csv(file_path, header=None)  # No header in your CSV
    ivs = []
    ciphertexts = []

    for _, row in df.iterrows():
        iv = row[:3].tolist()  # First three columns as IV
        ciphertext = row[3:].tolist()  # Remaining columns as ciphertext
        ivs.append(iv)
        ciphertexts.append(ciphertext)

    return ivs, ciphertexts


# Organize IVs by their starting value of a
def organize_ivs_by_a(ivs, ciphertexts):
    organized_ivs = {}

    for iv, ciphertext in zip(ivs, ciphertexts):
        a = iv[0]  # a is the first element of the IV
        if a not in organized_ivs:
            organized_ivs[a] = {'ivs': [], 'ciphertexts': []}

        organized_ivs[a]['ivs'].append(iv)
        organized_ivs[a]['ciphertexts'].append(ciphertext)

    return organized_ivs


def fms_attack(organized_ivs):
    key_bytes = []

    # The keystream byte O relates to the plaintext byte B
    B = 0xAA  # The SNAP header byte for the first position

    # Iterate over key indices (for each IV with distinct 'a')
    for a in sorted(organized_ivs.keys()):
        possible_keys = []

        for iv, ciphertext in zip(organized_ivs[a]['ivs'], organized_ivs[a]['ciphertexts']):
            # Use the first 3 bytes of the IV (weak IV assumption)
            K = iv[:3] + key_bytes  # Append known key bytes

            # Initialize the state with KSA
            S = ksa(K)

            j = 0
            # Perform the KSA swaps to set up the state
            for i in range(len(K)):
                j = (j + S[i] + K[i]) % 256
                S[i], S[j] = S[j], S[i]  # Swap

            # Run PRGA to get the next byte of the keystream
            keystream_gen = prga(S)
            O = next(keystream_gen)  # Get first keystream byte

            # FMS assumption: first byte of ciphertext is O XOR B
            possible_key_byte = (ciphertext[0] ^ B)  # B is 0xAA

            # Check if it matches and record the possible key byte
            possible_keys.append(S[3])

        # Take the most common byte as the correct key byte
        if possible_keys:
            most_common_key_byte = Counter(possible_keys).most_common(1)[0][0]
            key_bytes.append(most_common_key_byte)

    return key_bytes


if __name__ == '__main__':
    # Example usage
    file_path = 'packets.csv'  # Replace with your actual CSV file path
    ivs, ciphertexts = load_ivs_from_csv(file_path)

    # Organize the loaded IVs and ciphertexts by the starting value of a
    organized_ivs = organize_ivs_by_a(ivs, ciphertexts)

    # Perform the FMS attack
    key = fms_attack(organized_ivs)

    # Print the derived key
    print("Derived Key Bytes:", key)
