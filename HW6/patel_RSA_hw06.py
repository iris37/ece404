#!/usr/bin/env python
from BitVector import BitVector
import PrimeGenerator as pg
import sys
import os

# Importing from PrimeGenerator.py from lecture notes
generator = pg.PrimeGenerator(bits=128)

class RSA(object):
    def __init__(self, encrypt_or_decrypt):
        if encrypt_or_decrypt == 'encrypt':
            self.e = 65537
            self.p, self.q, self.n = self.get_modulus()
            self.d = self.get_decryption_exp()

            # Throwing important values to file
            with open("info.txt", 'w') as f:
                f.write(str(self.e))
                f.write('\n')
                f.write(str(self.p))
                f.write('\n')
                f.write(str(self.q))
                f.write('\n')
                f.write(str(self.n))
                f.write('\n')
                f.write(str(self.d))
        else:
            with open("info.txt", 'r') as f:
                info = f.readlines()
            self.e = int(info[0])
            self.p, self.q, self.n = int(info[1]), int(info[2]), int(info[3])
            self.d = int(info[4])

    def GCD(self, a, b):
        while b:
            a,b = b, a%b
        return a

    def MI(self, num, mod):
        '''
        This function uses ordinary integer arithmetic implementation of the
        Extended Euclid's Algorithm to find the MI of the first-arg integer
        vis-a-vis the second-arg integer.

        This is taken from lecture notes.
        '''
        NUM = num; MOD = mod
        x, x_old = 0, 1
        y, y_old = 1, 0
        while mod:
            q = num // mod
            num, mod = mod, num % mod
            x, x_old = x_old - q * x, x
            y, y_old = y_old - q * y, y
        if num != 1:
            MI = 0
        else:
            MI = (x_old + MOD) % MOD
        return MI

    def get_modulus(self):
        while True:
            p = generator.findPrime()
            q = generator.findPrime()

            gcd_p = self.GCD(p-1, 65537)
            gcd_q = self.GCD(q-1, 65537)

            MSB_p, MSB2_p = bin(p)[2:][0], bin(p)[2:][1]
            MSB_q, MSB2_q = bin(q)[2:][0], bin(q)[2:][1]

            if p != q and gcd_p == 1 and gcd_q == 1 and MSB_p == '1' and MSB2_p == '1' and \
                                                        MSB_q == '1' and MSB2_q == '1':
                modulus = p * q
                break
        return p, q, modulus

    def get_decryption_exp(self):
        d = self.MI(65537, ((self.p-1)*(self.q-1)))
        return d

    def fix_file(self, filename):
        with open(filename, 'r') as f:
            contents = f.readlines()[0]

        chars_to_add = (len(contents)*8) % 128

        if chars_to_add > 0:
            chars_to_add = (128 - chars_to_add) / 8
            with open(filename, 'a') as f:
                while chars_to_add > 0:
                    f.write('\n')
                    chars_to_add -= 1
        return

    def CRT(self, encrypted_int):
        Vp = pow(encrypted_int, self.d, self.p)
        Vq = pow(encrypted_int, self.d, self.q)
        Xp = self.q * (self.MI(self.q, self.p))
        Xq = self.p * (self.MI(self.p, self.q))
        return (Vp*Xp + Vq*Xq) % self.n

    def RSA_encrypt(self):
        f = open("encrypt_hex.txt", 'a')
        FILEOUT = open(sys.argv[3], 'a')
        self.fix_file(sys.argv[2])
        bv = BitVector(filename=sys.argv[2])
        while bv.more_to_read:
            bit_block = bv.read_bits_from_file(128)
            bit_block.pad_from_right(128-len(bit_block))
            bit_block.pad_from_left(128)
            encrypted_int = pow(int(bit_block), self.e, self.n)
            encrypted = BitVector(intVal=encrypted_int, size=256)
            encrypted.write_to_file(FILEOUT)
            f.write(encrypted.get_hex_string_from_bitvector())
        FILEOUT.close()
        return

    def RSA_decrypt(self):
        f = open("decrypt_hex.txt", 'a')
        FILEOUT = open(sys.argv[3], 'a')
        bv = BitVector(filename=sys.argv[2])
        while bv.more_to_read:
            bit_block = bv.read_bits_from_file(256)
            decrypted = self.CRT(int(bit_block))
            decrypted_unpadded = BitVector(intVal=decrypted, size=256)[128:]
            decrypted_unpadded.write_to_file(FILEOUT)
            f.write(decrypted_unpadded.get_hex_string_from_bitvector())
        FILEOUT.close()
        return

if __name__ == '__main__':
    import os

    if sys.argv[1] == '-e':
        if os.path.isfile("decrypt_hex.txt"):
            os.remove("decrypt_hex.txt")

        if os.path.isfile("decrypt.txt"):
            os.remove("decrypt.txt")

        if os.path.isfile("encrypt_hex.txt"):
            os.remove("encrypt_hex.txt")

        if os.path.isfile("output.txt"):
            os.remove("output.txt")

        rsa = RSA(encrypt_or_decrypt='encrypt')
        rsa.RSA_encrypt()
    else:
        rsa = RSA(encrypt_or_decrypt='decrypt')
        rsa.RSA_decrypt()
