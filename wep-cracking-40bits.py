import struct


def sim_resol(iv, key, byte_index, out):
    """
    Simulates part of the RC4 key scheduling.

    Parameters:
    - iv: The Initialization Vector (3 bytes)
    - key: The current key being tested (5 bytes)
    - byte_index: The index of the key byte we are currently resolving
    - out: The expected output byte after processing

    Returns:
    - An integer representing the resolved byte or -1 if invalid.
    """
    # Initialize the state array for RC4
    s = list(range(256))

    # Combine IV and key into a temporary key
    tmp_key = iv + key

    j = k = 0  # Initialize indices for the RC4 algorithm

    # Key Scheduling Algorithm (KSA) simulation
    for i in range(byte_index + 3):  # Include 3 bytes from IV
        j = (j + s[i] + tmp_key[k]) % 256  # Update index j
        s[i], s[j] = s[j], s[i]  # Swap values in state array

        # Loop over key bytes
        if k < len(tmp_key) - 1:
            k += 1
        else:
            k = 0  # Reset k if it exceeds the key length

    # Find the output byte's index in the state array
    s_1 = s.index(out) if out in s else -1

    # Check if the state array is valid
    if s[0] != byte_index + 3 or s[1] != 0:
        return -1  # Return -1 if invalid state
    return (s_1 - j - s[byte_index + 3]) % 256  # Return resolved byte index


def crack_wep(wep_file):
    """
    Main function to crack WEP keys from a .wep file.

    Parameters:
    - wep_file: Path to the WEP file containing encrypted packets.
    """
    key = bytearray(5)  # Initialize a 5-byte array for the key

    # Loop over each byte of the key
    for byte_index in range(len(key)):
        counts = [0] * 256  # Array to count occurrences of each byte

        # Open the WEP file in binary mode
        with open(wep_file, "rb") as fd:
            while True:
                tmp_line = fd.read(143)  # Read a packet (143 bytes)
                if not tmp_line:
                    break  # Exit loop if end of file

                # Check if the packet matches the criteria for processing
                if tmp_line[24] == byte_index + 3 and tmp_line[25] == 255:
                    out = ord('C') ^ tmp_line[27]  # XOR with assumed plaintext 'C'

                    # Call sim_resol to determine possible key byte
                    tmp = sim_resol(tmp_line[24:27], key, byte_index, out)

                    # Update counts for valid resolved bytes
                    if 0 <= tmp <= 255:
                        counts[tmp] += 1

        # Find the key byte with the highest count
        max_count = max(counts)  # Get the maximum count
        key[byte_index] = counts.index(max_count)  # Get the corresponding byte

    # Print the recovered key as a string
    print("Recovered key:", key.decode('latin-1'))  # Decode the byte array to string


if __name__ == "__main__":
    crack_wep("logs/log1.wep")
