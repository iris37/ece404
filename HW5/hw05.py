__author__ = 'Parth'

# Homework Number: 5
# Name: Parth Patel
# ECN Login: patel344
# Due Date: February 16, 2017

import io
import copy


class RC4(object):
    def __init__(self, key):
        assert type(key) == str, "Key must be string format of 16 ASCII Characters."
        assert len(key) == 16, "Key must be 128 bits (16 ASCII characters)"
        self.key = [ord(x) for x in list(key)]
        self.S = self.get_s(self.key)

    @staticmethod
    def load(image):
        with open(image, 'rb') as f:
            header = f.read(16)      # SPECIFIC TO WINTERTOWN.PPM (used to see decrypted and encrypted image)
            image = f.read()
        return header, image

    @staticmethod
    def get_s(key):
        S = list(range(256))
        T = [key[i % len(key)] for i in range(256)]

        # Key Scheduling Assignment
        j = 0
        for i in range(256):
            j = (j + S[i] + T[i]) % 256
            temp = S[i]
            S[i] = S[j]
            S[j] = temp
        return S

    def encrypt(self, filename):
        _, string = self.load(filename)
        f = io.BytesIO()
        S = copy.deepcopy(self.S)

        i = 0
        j = 0
        for c in string:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = (S[i] + S[j]) % 256
            encrypted = chr(S[k] ^ ord(c))
            f.write(encrypted)
        return f


    def decrypt(self, filepointer):
        f = io.BytesIO()
        S = copy.deepcopy(self.S)
        i = 0
        j = 0

        string = filepointer.getvalue()
        for c in string:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = (S[i] + S[j]) % 256
            decrypted = chr(S[k] ^ ord(c))
            f.write(decrypted)
        return f

if __name__ == '__main__':
    import filecmp

    rc4 = RC4('A1B2C3D4E5F6G7H8')
    header, _ = rc4.load("winterTown.ppm")
    e = rc4.encrypt("winterTown.ppm")
    d = rc4.decrypt(e)

    with open("encryptedImage.ppm", 'wb') as f:
        f.write(header)
        f.write(e.getvalue())
    with open("decryptedImage.ppm", 'wb') as f:
        f.write(header)
        f.write(d.getvalue())

    print
    filecmp.cmp("decrypted.ppm", "winterTownNoHeader.ppm")
