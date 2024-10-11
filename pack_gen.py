import sys
import csv


# RC4 Key Scheduling Algorithm (KSA)
def ksa(key):
    S = [i for i in range(256)]
    j = 0
    key_length = len(key)

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values in the S array

    return S


# RC4 Pseudo-Random Generation Algorithm (PRGA)
def prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values in the S array
        K = S[(S[i] + S[j]) % 256]
        yield K  # Yield the next keystream byte


# RC4 encryption/encryption
def rc4(key, data):
    S = ksa(key)
    keystream = prga(S)
    return bytes([byte ^ next(keystream) for byte in data])  # Returns a list if we want to have more encrypted bytes


# Function to generate weak IVs of the form (a+3, 255, x)
def generate_weak_ivs_first_form(key_length):
    weak_ivs = []
    for a in range(key_length):
        for third_byte in range(256):
            weak_iv = (a + 3, 255, third_byte)
            weak_ivs.append(weak_iv)
    return weak_ivs


# Function to generate weak IVs of the form (v, 257 - v, 255) starting from v = 2
def generate_weak_ivs_second_form():
    weak_ivs = []
    for v in range(2, 256):  # v starts from 2 to 255
        weak_iv = (v, 257 - v, 255)
        weak_ivs.append(weak_iv)
    return weak_ivs


# Function to encrypt using RC4 with the given IVs and key
def encrypt_with_weak_ivs(weak_ivs, key, snap_header):
    encrypted_rows = []

    for iv in weak_ivs:
        session_key = list(iv) + key  # Concatenate IV with the WEP key

        # Encrypt the snap_header using RC4
        encrypted = rc4(session_key, snap_header)

        # iv is a set. We will add it value by value and then the SNAP header byte
        encrypted_rows.append((*iv, encrypted[0]))

    return encrypted_rows


# Function to check if a string is a valid hexadecimal value
def is_hexadecimal(s):
    try:
        int(s, 16)  # Try to convert to integer
        return True
    except ValueError:
        return False


def main(key=None):
    if key is None:
        if len(sys.argv) != 2:
            print("user input key (in hex) should be second argument")
            sys.exit()
        raw_key = sys.argv[1]
    else:
        raw_key = key
    snap_header_hex = "AA"

    # Check if the provided raw_key is a valid hexadecimal string
    if not is_hexadecimal(raw_key):
        print(f"Error: '{raw_key}' is not a valid hexadecimal value.")
        sys.exit(1)

    # Convert hex key to bytes
    key = [int(raw_key[i:i + 2], 16) for i in range(0, len(raw_key), 2)]
    key_length = len(key)

    # Convert hex snap header to bytes
    snap_header = bytes.fromhex(snap_header_hex)

    # Generate weak IVs of the form (a + 3, 255, x)  for the given key length
    weak_ivs_first_form = generate_weak_ivs_first_form(key_length)

    # Generate IVs of the form (v, 257 - v, 255)  for the given key length
    weak_ivs_second_form = generate_weak_ivs_second_form()

    # encrypt the packet using weak IVs and get results
    encrypted_rows_first_form = encrypt_with_weak_ivs(weak_ivs_first_form, key, snap_header)
    encrypted_rows_second_form = encrypt_with_weak_ivs(weak_ivs_second_form, key, snap_header)

    # Write the results to a CSV file
    csv_filename = "packets.csv"
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)

        # First, write rows from encrypted_rows_first_form where the first column is 3 (for first byte of key)
        for row in encrypted_rows_first_form:
            if row[0] == 3:  # If they have IV with a = 3
                writer.writerow(row)
            if row[0] != 3:
                break  # Save time to just pass through the first 256 values with a = 3

        # Then write all rows from encrypted_rows_second_form (for first byte of key)
        for row in encrypted_rows_second_form:
            writer.writerow(row)  # Write the second form after the first form with a = 3

        # Finally, write the remaining rows from encrypted_rows_first_form
        for row in encrypted_rows_first_form:
            if row[0] != 3:
                writer.writerow(row)

    print(f"Encrypted data and packets written to {csv_filename} successfully.")


# We observed that keys with FF inside them are cannot be discovered
# (probably because it goes again in the beginning because of modulo)
# Also, not all keys are cracked
if __name__ == "__main__":
    main("4341434343")  # CACCC
