from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11WEP
import struct


def rc4_ksa(key):
    """ Key Scheduling Algorithm for RC4 """
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]  # Swap values
    return s


def rc4_prga(s, plaintext_length):
    """ Pseudo-Random Generation Algorithm (PRGA) """
    i = j = 0
    keystream = []
    for _ in range(plaintext_length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]  # Swap
        keystream.append(s[(s[i] + s[j]) % 256])
    return keystream


def wep_decrypt(key, iv, ciphertext, icv):
    """ Decrypts WEP data using RC4 """
    rc4_key = iv + key  # Combine IV and key
    s = rc4_ksa(rc4_key)  # Key Scheduling Algorithm
    keystream = rc4_prga(s, len(ciphertext))  # Generate keystream

    # XOR ciphertext with keystream to get plaintext
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])

    # Decrypt and verify ICV
    decrypted_icv = struct.unpack('<L', plaintext[-4:])[0]
    plaintext = plaintext[:-4]  # Remove ICV from plaintext

    return plaintext, decrypted_icv == icv  # Return plaintext and success status


def read_wep_file(filename):
    """ Reads packets from a .wep file """
    packets = rdpcap(filename)  # Read packets using Scapy
    wep_packets = []

    for packet in packets:
        if packet.haslayer(Dot11WEP):
            # Extract IV (3 bytes), ciphertext, and ICV
            iv = packet.iv
            ciphertext = packet.wepdata
            icv = packet.icv
            wep_packets.append((iv, ciphertext, icv))  # Store the packets

    return wep_packets


def validate_key(key, wep_packets):
    """Check if a key is valid by attempting to decrypt the packets."""
    for iv, ciphertext, icv in wep_packets:
        plaintext, success = wep_decrypt(key, iv, ciphertext, icv)
        if success:
            return True, plaintext  # Return success and decrypted plaintext
    return False, None  # Return failure


def crack_wep(wep_file, key_list_file):
    """ Main function to crack WEP key """
    wep_packets = read_wep_file(wep_file)  # Read packets from the .wep file

    with open(key_list_file, 'r') as f:
        keys = [line.strip().encode() for line in f]  # Read possible keys and convert to bytes

    for key in keys:
        is_valid, plaintext = validate_key(key, wep_packets)  # Validate each key
        if is_valid:
            print(f"The actual WEP key is: {key.decode()}")  # Print the valid key
            print(f"Decrypted plaintext: {plaintext}")  # Optionally print decrypted plaintext
            return key.decode()  # Return the valid key

    print("No valid key found.")
    return None


if __name__ == '__main__':
    file_name = 'wep_64_ptw_01.cap'  # Replace with your WEP file
    key_list_file = 'password.lst'  # Replace with your key list file
    crack_wep(file_name, key_list_file)
