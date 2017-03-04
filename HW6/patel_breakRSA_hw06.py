#!/usr/bin/env python
from BitVector import BitVector
import PrimeGenerator as pg
import sys
import os
from solve_pRoot import solve_pRoot

# Importing from PrimeGenerator.py from lecture notes
generator = pg.PrimeGenerator(bits=128)

class BreakRSA(object):
    def __init__(self):
        self.e = 3

        # p, q, n for each public key
        self.key_info1 = self.get_modulus()
        self.key_info2 = self.get_modulus()
        self.key_info3 = self.get_modulus()

        # d for each private key
        self.d1 = self.get_decryption_exp(self.key_info1[0], self.key_info1[1])
        self.d2 = self.get_decryption_exp(self.key_info2[0], self.key_info2[1])
        self.d3 = self.get_decryption_exp(self.key_info3[0], self.key_info3[1])

        self.key_info = [self.key_info1, self.key_info2, self.key_info3]
        self.d = [self.d1, self.d2, self.d3]

        with open("cracked_info.txt", 'w') as f:
            f.write("p, q, n for three public keys")
            f.write('\n')
            f.write(str(self.key_info1))
            f.write('\n')
            f.write(str(self.key_info2))
            f.write('\n')
            f.write(str(self.key_info3))
            f.write('\n')
            f.write('\n')
            f.write("d for three private keys")
            f.write('\n')
            f.write(str(self.d1))
            f.write('\n')
            f.write(str(self.d2))
            f.write('\n')
            f.write(str(self.d3))

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

    def get_decryption_exp(self, p, q):
        d = self.MI(65537, ((p-1)*(q-1)))
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

    def CRT(self, enc1, enc2, enc3, N):
        N1 = N / self.key_info1[2]
        N2 = N / self.key_info2[2]
        N3 = N / self.key_info3[2]

        mi1 = self.MI(N1, self.key_info1[2])
        mi2 = self.MI(N2, self.key_info2[2])
        mi3 = self.MI(N3, self.key_info3[2])

        return (enc1 * N1 * mi1 + enc2 * N2 * mi2 + enc3 * N3 * mi3) % N

    def encrypt(self):
        hex_files = ['hex1.txt', 'hex2.txt', 'hex3.txt']
        enc_files = ['enc1.txt', 'enc2.txt', 'enc3.txt']
        for i in range(3):
            f = open(hex_files[i], 'a')
            FILEOUT = open(enc_files[i], 'a')
            self.fix_file(sys.argv[1])
            bv = BitVector(filename=sys.argv[1])
            while bv.more_to_read:
                bit_block = bv.read_bits_from_file(128)
                bit_block.pad_from_right(128-len(bit_block))
                bit_block.pad_from_left(128)
                encrypted_int = pow(int(bit_block), self.e, self.key_info[i][2])
                encrypted = BitVector(intVal=encrypted_int, size=256)
                encrypted.write_to_file(FILEOUT)
                f.write(encrypted.get_hex_string_from_bitvector())
            FILEOUT.close()
        return

    def crack(self):
        f = open("cracked_hex.txt", 'a')
        FILEOUT = open(sys.argv[2], 'a')
        N = int(self.key_info1[2]) * int(self.key_info2[2]) * int(self.key_info3[2])
        enc_files = ['enc1.txt', 'enc2.txt', 'enc3.txt']
        bv = BitVector(filename=enc_files[0])
        bv2 = BitVector(filename=enc_files[1])
        bv3 = BitVector(filename=enc_files[2])
        while bv.more_to_read:
            bit_block = bv.read_bits_from_file(256)
            bit_block2 = bv2.read_bits_from_file(256)
            bit_block3 = bv3.read_bits_from_file(256)
            decrypted = self.CRT(int(bit_block), int(bit_block2), int(bit_block3), N)

            # VERY UNRELIABLE --> Doesn't always terminate and not always accurate and very slow(May need to do a few runs)
            decrypted2 = solve_pRoot(3, decrypted)

            decrypted_unpadded = BitVector(intVal=decrypted2, size=256)[128:]
            decrypted_unpadded.write_to_file(FILEOUT)
            f.write(decrypted_unpadded.get_hex_string_from_bitvector())
        FILEOUT.close()
        return

if __name__ == '__main__':
    import os

    rsaBreak = BreakRSA()
    rsaBreak.encrypt()
    rsaBreak.crack()