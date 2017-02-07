#!/usr/bin/env python
__author__ = 'Parth'

# Homework Number: 3
# Name: Parth Patel
# ECN Login: patel344
# Due Date: February 2, 2017

from BitVector import BitVector
AES_modulus = BitVector(bitstring='100011011')

subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption


def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


def get_encryption_key():
    while True:
        with open("key.txt", 'r') as f:
            string_key = f.readlines()[0]
        if len(string_key) != 16:
            print("\nKey generation needs 16 characters exactly.  Try again.\n")
            continue
        else:
            break
    key = BitVector(textstring=string_key)
    return key


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant


def gen_key_schedule_128(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 44 keywords in the key schedule for 128 bit AES.  Each keyword is 32-bits
    #  wide. The 128-bit AES uses the first four keywords to xor the input block with.
    #  Subsequently, each of the 10 rounds uses 4 keywords from the key schedule. We will
    #  store all 44 keywords in the following list:
    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words


def encrypt(inputfile, outputfile):
    key = get_encryption_key()
    key_words = gen_key_schedule_128(key)
    subBytesTable,_ = genTables()
    bv = BitVector(filename=inputfile)
    statearray = [[0 for x in range(4)] for x range(4)]
    FILEOUT = open(outputfile, 'ab')
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(128)
        if len(bitvec) > 0:
            if len(bitvec) != 128:
                bitvec.pad_from_right(128-len(bitvec))

            # Filling in statearray and XORing
            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                    statearray[i][j] ^= key_words[i][8*j:8+(8*j)]

            # Round processing
            for round in range(10):

                # SubBytes
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = subBytesTable[statearray[i][j]]

                # ShiftRows
                for i in range(4):
                    statearray[i] = statearray [i] << i

                # ColumnMixing
                one_time    = BitVector(bitstring='00000001')
                two_times   = BitVector(bitstring='00000010')
                three_times = BitVector(bitstring='00000011')
                col_mix = [two_times, three_times, one_time, one_time]
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = statearray[i][j].gf_multiply_modular(col_mix[i], AES_modulus, 8)
                    col_mix = [col_mix[-1], col_mix[0], col_mix[1], col_mix[3]]

                # Add Round Key
                    for i in range(4):
                        for j in range(4):
                            statearray[i][j] ^= key_words[round+1][8*j:8+(8*j)]

            for i in range(4):
                for j in range(4):
                    statearray[i][j].write_to_file(FILEOUT)
    FILEOUT.close()
    return

def decrypt():
    pass


if __name__ == '__main__':
    key = get_encryption_key()
    ok = gen_key_schedule_128(key)
    print(len(ok))
    for i in ok:
        print(i.get_bitv)