#!/usr/bin/env python
__author__ = 'Parth'

# Homework Number: 2
# Name: Parth Patel
# ECN Login: patel344
# Due Date: January 26, 2017

import sys
from BitVector import *


expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9,
                         10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16,
                         17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23,
                         24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

pbox_permutation = [ 15,  6, 19, 20, 28, 11, 27, 16,
                      0, 14, 22, 25,  4, 17, 30,  9,
                      1,  7, 23, 13, 31, 26,  2,  8,
                     18, 12, 29,  5, 21, 10,  3, 24 ]

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


def get_sboxes(filename):
    s_boxes = [[]] * 8
    j = 0
    with open(filename, 'r') as f:
        content = f.readlines()
    for entry in content[1:]:
        if ":" in entry:
            j += 1
        if "\n" != entry and ":" not in entry:
            s_boxes[j].append(list(map(int, entry.split())))
    return s_boxes


def substitution(expanded_half_block):  # Takes in 48 bit expanded half-block
    s_boxes_output = BitVector(size=32)
    s_boxes = get_sboxes('s-box-tables.txt')
    blocks = [expanded_half_block[i*6:i*6+6] for i in range(8)]
    for i in range(len(blocks)):
        row_index = int(2*blocks[i][0] + blocks[i][-1])
        col_index = int(blocks[i][1:-1])
        s_boxes_output[i*4:i*4+4] = BitVector(intVal=s_boxes[i][row_index][col_index], size=4)
    return s_boxes_output  # Returns a 32 bit block


def permutation(s_box_output):  # Takes in 32 bit block from substitution output
    return s_box_output.permute(pbox_permutation)


def get_encryption_key():
    while True:
        with open("key.txt", 'r') as f:
            string_key = f.readlines()[0]
        if len(string_key) != 8:
            print("\nKey generation needs 8 characters exactly.  Try again.\n")
            continue
        else:
            break
    key = BitVector(textstring=string_key)
    key = key.permute(key_permutation_1)
    return key


def generate_round_keys(encryption_key):
    round_keys = []
    for round_count in range(16):
        [LKey, RKey] = encryption_key.divide_into_two()
        shift = shifts_for_round_key_gen[round_count]
        LKey << shift
        RKey << shift
        key = LKey + RKey
        round_key = key.permute(key_permutation_2)
        round_keys.append(round_key)
    return round_keys


def DES(inputfile, outputfile, decrypt=False):
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


if __name__ == '__main__':
    DES('message.txt', 'encrypted.txt')
    DES('encrypted.txt', 'decrypted.txt', True)
