import pandas as pd


# RC4 Key Scheduling Algorithm (KSA)
def ksa(key, stop_at_3=True):
    n = 256
    S = list(range(n))
    j = 0
    if stop_at_3:
        n = 3
    for i in range(n):
        j = (j + S[i] + key[i % len(key)]) % n
        S[i], S[j] = S[j], S[i]  # Swap

    return S


# Pseudo-Random Generation Algorithm (PRGA)
def prga(S):
    j = 0
    for i in range(3):
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        K = S[(S[i] + S[j]) % 256]
        yield K  # Generate the next byte of key_inputstream
    # K = S[(S[i] + S[j]) % 256]
    # return K


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
        if a == 2 or a > 7:
            continue
        if a not in organized_ivs:
            organized_ivs[a] = {'ivs': [], 'ciphertexts': []}

        organized_ivs[a]['ivs'].append(iv)
        organized_ivs[a]['ciphertexts'].append(ciphertext)

    return organized_ivs


# FMS Attack Implementation
def fms_attack(organized_ivs):
    key_bytes = []

    # The keystream byte O relates to the plaintext byte B
    # We assume the first B (the SNAP header) is 0xAA
    B = 0xAA  # The SNAP header

    # Iterate over each key index (for each a value)
    for a in sorted(organized_ivs.keys()):
        possible_keys = []
        for iv, ciphertext in zip(organized_ivs[a]['ivs'], organized_ivs[a]['ciphertexts']):
            # print(len(organized_ivs[a]['ivs']))
            # Use the first 3 bytes of the IV
            K = iv[:3]

            K += key_bytes

            # Initialize S using the KSA
            # S = ksa(K)
            S = [0] * 256
            for i in range(256):
                S[i] = i

            # Perform the first <len(K)> iterations of KSA to initialize the state machine
            j = 0
            for i in range(len(K)):
                j = (j + S[i] + K[i]) % 256
                S[i], S[j] = S[j], S[i]  # Swap

            # Now generate the keystream output
            # ciphertext[0] = 0xAA ^ O
            O = 0xAA ^ ciphertext[0]  # The first keystream byte is this, since we know the plaintext

            possible_key_byte = (O - j - S[len(K)]) % 256  # Compute the next possible key byte
            possible_keys.append(possible_key_byte)

        # Identify the most common byte as the next byte of the key
        if possible_keys:
            print(possible_keys)
            most_common_key_byte = max(set(possible_keys), key=possible_keys.count)
            key_bytes.append(most_common_key_byte)

    return key_bytes


if __name__ == '__main__':
    # Example usage
    file_path = '../packets.csv'  # Replace with your actual CSV file path
    ivs, ciphertexts = load_ivs_from_csv(file_path)

    # Organize the loaded IVs and ciphertexts by the starting value of a
    organized_ivs = organize_ivs_by_a(ivs, ciphertexts)

    # Perform the FMS attack
    key = fms_attack(organized_ivs)
    hex_key = 0x0
    for i in range(len(key)):
        hex_key += key[-(i + 1)] * (256 ** i)

    # Print the derived key
    print("Derived Key:", key, hex(hex_key))
