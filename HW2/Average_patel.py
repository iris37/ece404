#!/usr/bin/env python
__author__ = 'Parth'

# Homework Number: 2
# Name: Parth Patel
# ECN Login: patel344
# Due Date: January 26, 2017
import pprint
import random
import os
import copy
from DES_patel import *


def file_as_bits(inputfile):
    read_bits = os.path.getsize(inputfile) * 8
    bv = BitVector(filename=inputfile)
    bitvec = bv.read_bits_from_file(read_bits)
    return bitvec

def bit_changes(f1, f2):
    bits1 = file_as_bits(f1)
    bits2 = file_as_bits(f2)
    changes = bits1 ^ bits2
    return changes.count_bits(), len(bits1) / 64


def populate_sboxes():
    x = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    s_boxes = {i:None for i in range(8)}

    for i in range(8):
        random.shuffle(x)
        a = copy.deepcopy(x)
        random.shuffle(x)
        b = copy.deepcopy(x)
        random.shuffle(x)
        c= copy.deepcopy(x)
        random.shuffle(x)
        d = copy.deepcopy(x)
        s_boxes[i] = [a,b,c,d]
    return s_boxes


def substitution(expanded_half_block):  # Takes in 48 bit expanded half-block
    s_boxes_output = BitVector(size=32)
    s_boxes = populate_sboxes()
    blocks = [expanded_half_block[i*6:i*6+6] for i in range(8)]
    for i in range(len(blocks)):
        row_index = int(2*blocks[i][0] + blocks[i][-1])
        col_index = int(blocks[i][1:-1])
        s_boxes_output[i*4:i*4+4] = BitVector(intVal=s_boxes[i][row_index][col_index], size=4)
    return s_boxes_output  # Returns a 32 bit block


def DES_diff_sboxes(inputfile, outputfile, decrypt=False):
    key = get_encryption_key()
    round_keys = generate_round_keys(key)
    if decrypt:
        round_keys.reverse()
    bv = BitVector(filename=inputfile)
    FILEOUT = open(outputfile, 'ab')
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(64)
        if len(bitvec) > 0:
            if len(bitvec) != 64:
                bitvec.pad_from_right(64-len(bitvec))
            [LE, RE] = bitvec.divide_into_two()
            for round_key in round_keys:
                newRE = RE.permute(expansion_permutation)
                out_xor = newRE ^ round_key
                sbox_output = substitution(out_xor)
                pbox_output = permutation(sbox_output)
                RE_modified = pbox_output ^ LE
                LE = RE
                RE = RE_modified
            final_bitvec = RE + LE
            final_bitvec.write_to_file(FILEOUT)
    FILEOUT.close()
    return


def diffusion_plaintext(inputfile):
    orig_plaintext_bits = file_as_bits(inputfile)
    bit_to_change = random.randrange(orig_plaintext_bits.length())
    orig_plaintext_bits[bit_to_change] ^= 1

    FILEOUT = open("altered_plaintext.txt", 'ab')
    orig_plaintext_bits.write_to_file(FILEOUT)
    FILEOUT.close()

    DES(inputfile, "ciphertext_orig.txt")
    DES("altered_plaintext.txt", "ciphertext_altered.txt")

    changed_bits, num_blocks = bit_changes("ciphertext_orig.txt", "ciphertext_altered.txt")

    os.remove("ciphertext_orig.txt")
    os.remove("altered_plaintext.txt")
    os.remove("ciphertext_altered.txt")

    return changed_bits, changed_bits / num_blocks


def diffusion_sboxes(inputfile):
    DES(inputfile, "ciphertext_orig.txt")
    DES_diff_sboxes(inputfile, "ciphertext_diff_sbox1.txt")
    DES_diff_sboxes(inputfile, "ciphertext_diff_sbox2.txt")

    changed_bits1, num_blocks1 = bit_changes("ciphertext_orig.txt", "ciphertext_diff_sbox1.txt")
    changed_bits2, num_blocks2 = bit_changes("ciphertext_orig.txt", "ciphertext_diff_sbox2.txt")

    os.remove("ciphertext_orig.txt")
    os.remove("ciphertext_diff_sbox1.txt")
    os.remove("ciphertext_diff_sbox2.txt")

    return changed_bits1, changed_bits1 / num_blocks1, changed_bits2, changed_bits2 / num_blocks2


def confusion(inputfile, key_file):
    DES(inputfile, "ciphertext_orig.txt")
    orig_key_bits = file_as_bits(key_file)
    bit_to_change = random.randrange(orig_key_bits.length())
    orig_key_bits[bit_to_change] ^= 1

    os.remove(key_file)

    FILEOUT = open(key_file, 'wb')
    orig_key_bits.write_to_file(FILEOUT)
    FILEOUT.close()

    DES(inputfile, "ciphertext_altered.txt")

    changed_bits, num_blocks = bit_changes("ciphertext_orig.txt", "ciphertext_altered.txt")

    os.remove("ciphertext_orig.txt")
    os.remove("ciphertext_altered.txt")

    return changed_bits, changed_bits / num_blocks


if __name__ == '__main__':
    # Problem 1
    total_changed, avg_bits_changed = diffusion_plaintext("message.txt")
    print(total_changed, avg_bits_changed)

    # Problem 2
    total_changed1, avg_bits_changed1, total_changed2, avg_bits_changed2 = diffusion_sboxes("message.txt")
    print(total_changed1, avg_bits_changed1, total_changed2, avg_bits_changed2)

    # Problem 3
    total = 0
    for key in ["ecepurdu", "direwolf", 'oldmaner', 'abcdefgh']:
        os.remove("key.txt")
        with open("key.txt", 'w') as f:
            f.write(key)

        total_changed, avg_bits_changed = confusion("message.txt", "key.txt")
        total += avg_bits_changed
    print(total_changed)
    print (total / 4)

    '''
        Problem 1:

            Total Bits Changed in Ciphertext: 4590
            Average bits changed per 64 bit block : 22.58

        Problem 2:

            For Random Sbox Generation 1:
                Total Bits Changed in Ciphertext: 5931
                Average bits changed per 64 bit block : 29.18

            For Random Sbox Generation 2:
                Total Bits Changed in Ciphertext: 5951
                Average bits changed per 64 bit block : 29.28

        Problem 3:

             Total Bits Changed in Ciphertext for all 4 keys: 5946
            Average bits changed per 64 bit block: 29.25
    '''