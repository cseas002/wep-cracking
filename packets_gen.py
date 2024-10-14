import sys
import csv
import argparse


# RC4 Key Scheduling Algorithm (KSA)
def ksa(key):
    """
    Initializes the RC4 state array (S) using the provided key.

    :param key: The key used for the KSA process, given as a list of integers (bytes).
    :return: The initialized S array.
    """
    S = [i for i in range(256)]
    j = 0
    key_length = len(key)

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap values in the S array

    return S


# RC4 Pseudo-Random Generation Algorithm (PRGA)
def prga(S):
    """
    Generates the RC4 keystream using the initialized S array.

    :param S: The initialized S array from the KSA.
    :yield: The next byte of the keystream.
    """
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
    """
    Encrypts or decrypts data using the RC4 algorithm with the provided key.

    :param key: The RC4 key as a list of bytes.
    :param data: The plaintext or ciphertext to encrypt/decrypt as bytes.
    :return: The encrypted or decrypted data as bytes.
    """
    S = ksa(key)
    keystream = prga(S)
    return bytes([byte ^ next(keystream) for byte in data])  # Returns a list if we want to have more encrypted bytes


# Function to generate weak IVs of the form (a+3, 255, x)
def generate_weak_ivs_first_form(key_length):
    """
    Generates weak IVs of the form (a+3, 255, x) for a given key length.

    :param key_length: Length of the WEP key.
    :return: List of weak IVs in the form of tuples.
    """
    weak_ivs = []
    for a in range(key_length):
        for third_byte in range(256):
            weak_iv = (a + 3, 255, third_byte)
            weak_ivs.append(weak_iv)
    return weak_ivs


# Function to generate weak IVs of the form (v, 257 - v, 255) starting from v = 2
def generate_weak_ivs_second_form():
    """
    Generates weak IVs of the form (v, 257 - v, 255) starting from v = 2.

    :return: List of weak IVs in the form of tuples.
    """
    weak_ivs = []
    for v in range(2, 256):  # v starts from 2 to 255
        weak_iv = (v, 257 - v, 255)
        weak_ivs.append(weak_iv)
    return weak_ivs


# Function to encrypt using RC4 with the given IVs and key
def encrypt_with_weak_ivs(weak_ivs, key, snap_header):
    """
    Encrypts the given SNAP header (0xAA) with RC4 using the weak IVs and the provided key.

    :param weak_ivs: List of weak IVs in the form of tuples.
    :param key: The WEP key as a list of bytes.
    :param snap_header: The SNAP header as bytes.
    :return: A list of tuples, where each tuple contains an IV and the first byte of the encrypted SNAP header.
    """
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
    """
   Checks if a given string is a valid hexadecimal value.

   :param s: The string to check.
   :return: True if the string is a valid hexadecimal, False otherwise.
   """
    try:
        int(s, 16)  # Try to convert to integer
        return True
    except ValueError:
        return False


def main(key=None, output_filename="packets.csv"):
    """
    Main function to encrypt packets using RC4 with weak IVs and write them to a CSV file.

    :param key: The WEP key as a hexadecimal string. If not provided, the script will read it from the command line.
    :param output_filename: The filename to save the encrypted packets. Defaults to 'packets.csv'.
    """
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

    with open(output_filename, mode='w', newline='') as file:
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

    print(f"Encrypted data and packets written to {output_filename} successfully.")


# We observed that keys with FF inside them are cannot be discovered
# (probably because it goes again in the beginning because of modulo)
# Also, not all keys are cracked
if __name__ == "__main__":
    # Use argparse for more flexible argument parsing
    parser = argparse.ArgumentParser(description="Generate WEP packets with weak IVs.")
    parser.add_argument('key', nargs='?', default="4341434343", help="WEP key in hex format (default: 4341434343)")
    parser.add_argument('--output_filename', type=str, default="packets.csv", help="Output CSV file name (default: packets.csv)")

    # Parse the arguments
    args = parser.parse_args()

    # Run main with the parsed key and output filename
    main(key=args.key, output_filename=args.output_filename)
