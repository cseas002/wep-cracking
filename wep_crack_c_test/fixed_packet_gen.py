import sys
from wep_crack_c_test.rc4 import *


def main(key=None):
    possibleByte = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A', 'B', 'C', 'D', 'E', 'F',
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    if key is None:
        if len(sys.argv) != 2:
            print("user input key (in hex) should be second argument")
            sys.exit()
        rawkey = sys.argv[1]
    else:
        rawkey = key

    if len(rawkey) % 2 != 0:
        print("key is not right, its length should be a multiple of 2")
        sys.exit()

    for i in rawkey:
        if i not in possibleByte:
            print(rawkey)
            print(i)
            print(type(i))
            print("key should only contains 0-9 and A-F.")
            sys.exit()

    key = []
    i = 0
    while i < len(rawkey):
        key.append(int(rawkey[i] + rawkey[i + 1], 16))  # 0-255 (0x0 - 0xFF)
        i += 2

    # Initial IV form.
    iv = [3, 255, 0]
    sessionKey = iv + key
    plainSNAP = "aa"

    # Clear out what is originally in the file.
    packets = open("../packets.csv", "w").close()
    # Append possible IV and keyStreamByte.
    packets = open("../packets.csv", "a")

    # a is the number of known key bytes, it starts from 0 to the length of key.
    # See https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack

    # Add initialization vectors in the form (a + 3, 255, v)
    # a represents the index of the byte of the WEP key we're trying to attack
    for a in range(len(key)):
        iv[0] = a + 3  # Since the first 3 bytes are the IV, the key starts from the 4th byte
        for thirdByte in range(256):
            iv[2] = thirdByte
            sessionKey = iv + key  # Concatenate IV with the key
            sbox = []
            initSBox(sbox)
            ksaInt(sessionKey, sbox)

            i = 0
            j = 0
            i = (i + 1) % 256
            j = (j + sbox[i]) % 256
            swapValueByIndex(sbox, i, j)
            keyStreamByte = sbox[(sbox[i] + sbox[j]) % 256]
            cipherByte = (int(plainSNAP, 16)) ^ keyStreamByte
            packets.write(str(iv[0]) + "," + str(iv[1]) + "," + str(iv[2]) + "," + str(cipherByte) + "\n")

    # Add initialization vectors in the form (v, 257 - v, 255)
    for i in range(254):
        v = i + 2
        iv = [v, 257 - v, 255]
        sessionKey = iv + key  # Concatenate IV with the key
        sbox = []
        initSBox(sbox)
        ksaInt(sessionKey, sbox)
        i = 0
        j = 0
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        swapValueByIndex(sbox, i, j)
        keyStreamByte = sbox[(sbox[i] + sbox[j]) % 256]
        cipherByte = (int(plainSNAP, 16)) ^ keyStreamByte
        packets.write(str(iv[0]) + "," + str(iv[1]) + "," + str(iv[2]) + "," + str(cipherByte) + "\n")

    print("packets.csv is generated successfully.")


if __name__ == '__main__':
    main("422153")
