from scapy.all import rdpcap, conf
from scapy.layers.dot11 import Dot11, Dot11WEP  # Import Dot11 and Dot11WEP for 802.11 packet handling
import binascii
import struct
import os

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
    # Combine IV and key
    rc4_key = iv + key
    s = rc4_ksa(rc4_key)
    keystream = rc4_prga(s, len(ciphertext))
    
    # XOR ciphertext with keystream to get plaintext
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
    
    # Decrypt and verify ICV
    decrypted_icv = struct.unpack('<L', plaintext[-4:])[0]
    plaintext = plaintext[:-4]
    
    if decrypted_icv == icv:
        return plaintext, True
    else:
        return None, False

def read_cap_file(filename):
    """ Reads packets from a .cap file """
    packets = rdpcap(filename)
    wep_packets = []
    
    for packet in packets:
        if packet.haslayer(Dot11WEP):
            # Extract IV (3 bytes), ciphertext, and ICV
            iv = packet.iv
            ciphertext = packet.wepdata
            icv = packet.icv
            wep_packets.append((iv, ciphertext, icv))
    
    return wep_packets

def read_wep_file(filename):
    """ Reads packets from a .wep file """
    wep_packets = []
    
    with open(filename, 'rb') as f:
        while True:
            # Read the IV (3 bytes) + Data (up to 1500 bytes) + ICV (4 bytes)
            header = f.read(3)  # IV
            if not header:
                break
            
            iv = header
            # Assuming the rest of the data is the ciphertext + ICV
            ciphertext = f.read(1500)  # Read up to the next 1500 bytes
            if not ciphertext:
                break
            
            icv = f.read(4)  # ICV
            
            if len(icv) < 4:
                break
            
            wep_packets.append((iv, ciphertext[:-4], struct.unpack('<L', icv)[0]))  # Store the extracted data
    
    return wep_packets

def crack_wep(file_path, wordlist_file):
    """ Main function to crack WEP key """
    wep_packets = []
    
    # Check the file extension to read the appropriate file type
    _, file_extension = os.path.splitext(file_path)
    if file_extension == '.cap':
        wep_packets = read_cap_file(file_path)
    elif file_extension == '.wep':
        wep_packets = read_wep_file(file_path)
    else:
        print("Unsupported file type")
        return None
    
    with open(wordlist_file, 'r') as f:
        keys = [line.strip().encode() for line in f]
    
    for key in keys:
        for iv, ciphertext, icv in wep_packets:
            # Try to decrypt
            plaintext, success = wep_decrypt(key, iv, ciphertext, icv)
            if success:
                print(f"Key found: {key}")
                return key

    print("Key not found")
    return None

if __name__ == "__main__":
    crack_wep("logs/log1.wep", "passlist.txt")
