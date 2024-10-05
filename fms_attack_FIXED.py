import pandas as pd


# Load packets from a CSV file
def load_packets_from_csv(file_path):
    df = pd.read_csv(file_path, header=None)  # No header in your CSV
    packets = []

    for _, row in df.iterrows():
        packet = row.tolist()  # Each row as a single packet
        packets.append(packet)

    return packets


# FMS Attack Implementation
def fms_attack(packets):
    key_bytes = []
    possible_keys = []  # 2D list with 5 empty arrays
    previous_key_index = 0
    # Iterate over each packet
    index = 0
    # For packets with format (a + 3, 255, v)
    while index < len(packets):
        # The packets with format (v, 257 - v, 255), can help in recovering only the FIRST byte of the key
        # They are 254 packets
        while 256 <= index < 510:
            packet = packets[index]
            if len(packet) < 4:
                continue  # Skip if the packet is too short
            # Use the first 3 bytes of the packet as the IV
            K = packet[:3]

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
            possible_keys.append(possible_key_byte)  # Append in the possible byte for position a - 3 (so 0, 1, ...)
            index += 1

        if index >= len(packets):
            break
        packet = packets[index]
        if len(packet) < 4:
            continue  # Skip if the packet is too short

        # Use the first 3 bytes of the packet as the IV
        K = packet[:3]
        K += key_bytes
        key_index = K[0] - 3

        # If we reached an end to a key index (e.g., we found all the packets for index 0), we calculate the key byte of
        # that index
        if key_index != previous_key_index:
            previous_key_index = key_index
            # Identify the most common byte as the next byte of the key
            if possible_keys:
                most_common_key_byte = max(set(possible_keys), key=possible_keys.count)
                key_bytes.append(most_common_key_byte)
            possible_keys = []

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
        possible_keys.append(possible_key_byte)  # Append in the possible byte for position a - 3 (so 0, 1, ...)
        index += 1

    # Identify the most common byte as the last byte of the key
    if possible_keys:
        most_common_key_byte = max(set(possible_keys), key=possible_keys.count)
        key_bytes.append(most_common_key_byte)

    return key_bytes


if __name__ == '__main__':
    # Example usage
    file_path = 'packets.csv'  # Replace with your actual CSV file path
    packets = load_packets_from_csv(file_path)

    # Perform the FMS attack
    derived_key = fms_attack(packets)

    # Convert the derived key into hexadecimal format
    hex_key = 0x0
    for i in range(len(derived_key)):
        hex_key += derived_key[-(i + 1)] * (256 ** i)

    # Print the derived key
    print("Derived Key:", derived_key, hex(hex_key))
