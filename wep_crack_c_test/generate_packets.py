import os
import struct
import time
import rc4_OLD  # Assuming you have the RC4 implementation in rc4_OLD.py
import random

# Constants for WEP and pcap file format
WEP_PAYLOAD_SIZE = 1500  # Max payload size (adjust as needed)
WEP_CRC_SIZE = 4  # 32 bits (4 bytes for CRC)
WEP_KEY_SIZE = 5  # 5 bytes for WEP-40 key

# PCAP file header format
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 0, 0)


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

    packet_type = 0x00  # Adjust as needed, usually fixed
    payload = os.urandom(WEP_PAYLOAD_SIZE - 1)  # Random payload, minus 1 byte for the SNAP header

    # Add the SNAP header with the first byte set to 0xAA
    snap_header = bytes([0xAA]) + bytes(1) + bytes(2)  # Adjust as needed for a valid SNAP header

    # Encrypt the payload using RC4
    rc4_box = [0] * 256
    rc4_OLD.initSBox(rc4_box)  # Ensure the S-box is initialized
    rc4_OLD.ksa(key, rc4_box)  # Initialize RC4 key schedule
    keystream = rc4_OLD.prga(rc4_box)  # Generate the keystream
    encrypted_payload = bytearray()

    # Encrypt payload
    for byte in payload:
        encrypted_byte = byte ^ next(keystream)  # XOR with keystream
        encrypted_payload.append(encrypted_byte)

    # Calculate CRC for the encrypted payload
    crc = calculate_crc(encrypted_payload)

    # Build the WEP packet
    packet = weak_iv + bytes([packet_type]) + snap_header + encrypted_payload + struct.pack("<I", crc)
    return packet


def save_packets_to_cap(file_path, num_packets, key):
    """Generates packets and saves them to a .cap file for FMS attack."""
    with open(file_path, 'wb') as f:
        # Write the global header
        f.write(PCAP_GLOBAL_HEADER)

        for _ in range(num_packets):
            # Generate the IVs with first byte ranging from 3 to 7
            iv_first_byte = 3 + (_ % 5)  # Cycles through 3, 4, 5, 6, 7
            packet = generate_fms_iv_packet(key, iv_first_byte)
            timestamp = int(time.time())  # Current timestamp
            microseconds = 0  # Set microseconds to 0 for simplicity
            packet_length = len(packet)
            captured_length = packet_length  # Length captured matches actual length

            # Write the packet header
            f.write(struct.pack("<IIII", timestamp, microseconds, captured_length, packet_length))
            f.write(packet)


# Example usage
if __name__ == "__main__":
    output_file = "fms_attack_packets.cap"
    number_of_packets = 100  # Number of packets to generate

    # Define a 5-byte WEP-40 key (randomly generated for demonstration)
    wep_key = b'AAAAA'  # Ensure the key is bytes
    save_packets_to_cap(output_file, number_of_packets, wep_key)
    print(f"Generated {number_of_packets} weak IV packets for the FMS attack and saved to {output_file}.")
