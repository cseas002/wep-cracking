import csv
from collections import defaultdict

# Constants
SNAP_HEADER_FIRST_BYTE = 0xAA  # First byte of SNAP header (almost always 0xAA)
KEY_SIZE = 5  # Size of the WEP key (40-bit WEP = 5 bytes)


# Function to initialize the RC4 state array (S-box)
def initialize_rc4_state(iv, key_prefix):
    S = list(range(256))  # Initialize the S-box with sequential values from 0 to 255

    # Replace None values in key_prefix with 0 (since we don't know the key yet for those bytes)
    key_prefix_filled = [byte if byte is not None else 0 for byte in key_prefix]

    K = iv + key_prefix_filled  # Key schedule is IV followed by the known part of the key

    j = 0
    for i in range(len(K)):
        j = (j + S[i] + K[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap the values in the S-box

    return S, j


# Function to guess the next key byte based on the FMS attack
def guess_key_byte(S, j, keystream_byte, key_index):
    i = key_index + 3  # The first 3 bytes are from the IV
    j = (j + S[i]) % 256
    keystream_output = S[(S[i] + S[j]) % 256]

    # Calculate the possible key byte
    possible_key_byte = (keystream_byte - keystream_output) % 256
    return possible_key_byte


# Function to perform the FMS attack and crack the WEP key
def crack_wep_key(csv_file):
    key_guess = [None] * KEY_SIZE
    vote_table = [defaultdict(int) for _ in range(KEY_SIZE)]

    # Read the CSV file containing weak IV packets
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            packet = list(map(int, row))
            iv = packet[:3]  # First 3 bytes are the IV
            keystream_byte = packet[3] ^ SNAP_HEADER_FIRST_BYTE  # First byte of the keystream (XOR with 0xAA)

            # For each key byte we're trying to guess
            for key_index in range(KEY_SIZE):
                # Use the key bytes we've already guessed as the prefix
                key_prefix = key_guess[:key_index]  # Now we use the correct prefix

                # Fill None values with 0
                key_prefix_filled = [byte if byte is not None else 0 for byte in key_prefix]

                # Initialize RC4 state with current IV and partial key
                S, j = initialize_rc4_state(iv, key_prefix_filled)

                # Guess the key byte using the FMS attack
                possible_key_byte = guess_key_byte(S, j, keystream_byte, key_index)

                # Vote for the possible key byte
                vote_table[key_index][possible_key_byte] += 1

                # Debugging output
                print(f"Key Index: {key_index}, Possible Key Byte: {possible_key_byte}, Votes: {vote_table[key_index]}")

    # Choose the most likely key bytes from the vote table
    for i in range(KEY_SIZE):
        key_guess[i] = max(vote_table[i], key=vote_table[i].get)

    return key_guess


# Main function to run the WEP cracking
if __name__ == '__main__':
    csv_file = '../packets.csv'  # Path to your CSV file containing weak IVs
    key = crack_wep_key(csv_file)
    print(f"Cracked WEP key: {key}")
