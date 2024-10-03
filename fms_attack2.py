import pandas as pd


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
            # Use the first 3 bytes of the IV
            K = iv[:3]
            # key_byte_to_decrypt = a - 3  # We first decrypt the first byte (3 - 3), then second, etc.

            # We don't add any byte in the beginning, only the IV, since we don't know any more bytes,
            # then the first byte of ciphertext, then the first two bytes, etc.
            K += key_bytes

            # Initialize S using the KSA
            # S = ksa(K)
            S = list(range(256))

            # Perform the first <len(K)> iterations of KSA to initialize the state machine
            j = 0
            for i in range(len(K)):
                j = (j + S[i] + K[i]) % 256
                S[i], S[j] = S[j], S[i]  # Swap
                if i == 1:
                    original0 = S[0]
                    original1 = S[1]

            # Now generate the keystream output
            keystream_gen = prga(S)
            # Get the keystream byte
            O = next(keystream_gen)  # The next byte of the keystream

            keyStreamByte = B ^ ciphertext[0]

            possible_key_byte = (O - 0 - S[3]) % 256  # Compute K[<a>]

            possible_keys.append(possible_key_byte)

        # Identify the most common byte as the next byte of the key
        if possible_keys:
            most_common_key_byte = max(set(possible_keys), key=possible_keys.count)
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
