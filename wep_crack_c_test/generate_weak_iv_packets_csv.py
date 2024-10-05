import os
import struct
import time
import random
import csv
import rc4_OLD

# Constants for WEP
WEP_PAYLOAD_SIZE = 100  # Max payload size (adjust as needed)
WEP_KEY_SIZE = 5  # 5 bytes for WEP-40 key

# CSV header for weak IV packets
CSV_HEADER = ['IV', 'SNAP Header', 'Encrypted Payload', 'CRC']


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


def generate_fms_iv_packet(key, iv_first_byte):
    """Generates a WEP packet with a specified weak IV for the FMS attack."""
    # Generate IV of the form (a, 255, x) where a is from 3 to 7
    weak_iv = bytes([iv_first_byte, 255, random.randint(0, 255)])  # IV: (a, 255, x)

    # packet_type = 0x00  # Adjust as needed, usually fixed
    payload = os.urandom(WEP_PAYLOAD_SIZE - 1)  # Random payload, minus 1 byte for the SNAP header

    # Add the SNAP header with the first byte set to 0xAA
    snap_header = bytes([0xAA])   # Adjust as needed for a valid SNAP header

    encrypted_payload = rc4.encrypt_decrypt_payload(payload, key)

    # Calculate CRC for the encrypted payload
    crc = calculate_crc(encrypted_payload)

    return weak_iv, snap_header, encrypted_payload, crc


def save_packets_to_csv(file_path, num_packets, key):
    """Generates packets and saves them to a CSV file for FMS attack."""
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(CSV_HEADER)  # Write the header

        for _ in range(num_packets):
            # Generate the IVs with first byte ranging from 3 to 7
            iv_first_byte = 3 + (_ % 5)  # Cycles through 3, 4, 5, 6, 7
            weak_iv, snap_header, encrypted_payload, crc = generate_fms_iv_packet(key, iv_first_byte)

            # Convert all fields to hex strings for CSV
            weak_iv_hex = ','.join(f'{byte:02x}' for byte in weak_iv)
            snap_header_hex = ','.join(f'{byte:02x}' for byte in snap_header)
            encrypted_payload_hex = ','.join(f'{byte:02x}' for byte in encrypted_payload)
            crc_hex = f'{crc:08x}'

            # Write packet data to CSV
            csv_writer.writerow([weak_iv_hex, snap_header_hex, encrypted_payload_hex, crc_hex])


# Example usage
if __name__ == "__main__":
    output_file = "weak_iv_packets.csv"
    number_of_packets = 100  # Number of packets to generate

    # Define a 5-byte WEP-40 key (randomly generated for demonstration)
    wep_key = b'AAAAA'  # Ensure the key is bytes
    save_packets_to_csv(output_file, number_of_packets, wep_key)
    print(f"Generated {number_of_packets} weak IV packets for the FMS attack and saved to {output_file}.")
