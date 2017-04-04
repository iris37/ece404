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
    """
	Takes in a file and returns it in binary form.
    """
    read_bits = os.path.getsize(inputfile) * 8
    bv = BitVector(filename=inputfile)
    bitvec = bv.read_bits_from_file(read_bits)
    return bitvec

def bit_changes(f1,f2):
    """ Compares two files and returns
   	how many bits are different.
    """
    bits1 = file_as_bits(f1)
    bits2 = file_as_bits(f2)
    changes = bits1 ^ bits2
    return changes.count_bits(), bits1.length()/64


def populate_sboxes():
    """
	Randomaly populates 8 4x16 sboxes.
    """
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


def substitution(expanded_half_block, sboxes):  # Takes in 48 bit expanded half-block
    """
	Performs Substitution with a passed in sbox.
    """
    s_boxes_output = BitVector(size=32)
    s_boxes = sboxes
    blocks = [expanded_half_block[i*6:i*6+6] for i in range(8)]
    for i in range(len(blocks)):
        row_index = int(2*blocks[i][0] + blocks[i][-1])
        col_index = int(blocks[i][1:-1])
        s_boxes_output[i*4:i*4+4] = BitVector(intVal=s_boxes[i][row_index][col_index], size=4)
    return s_boxes_output  # Returns a 32 bit block


def DES_diff_sboxes(inputfile, outputfile, sboxes, decrypt=False):
    """
    	Altered DES to account for different sboxes.
    """
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
                sbox_output = substitution(out_xor, sboxes)
                pbox_output = permutation(sbox_output)
                RE_modified = pbox_output ^ LE
                LE = RE
                RE = RE_modified
            final_bitvec = RE + LE
            final_bitvec.write_to_file(FILEOUT)
    FILEOUT.close()
    return


def diffusion(inputfile, sbox=None):
    """
	One bit in the plaintext (inputfile) is changed.
	The new altered plaintext is written out to a file.
	If we are doing Problem 1 skip to else statement.
	If we are doing Problem 2 enter if block.
	In both scenarios DES is performed with the original and 
	altered plaintexts, and the outputs are compared.
    """
    orig_plaintext_bits = file_as_bits(inputfile)
    bit_to_change = random.randrange(orig_plaintext_bits.length())
    orig_plaintext_bits[bit_to_change] ^= 1

    FILEOUT = open("altered_plaintext.txt", 'wb')
    orig_plaintext_bits.write_to_file(FILEOUT)
    FILEOUT.close()
    if sbox:
	DES_diff_sboxes(inputfile, "ciphertext_orig.txt", sbox)
	DES_diff_sboxes("altered_plaintext.txt", "ciphertext_altered.txt", sbox)
    else:
    	DES(inputfile, "ciphertext_orig.txt")
    	DES("altered_plaintext.txt", "ciphertext_altered.txt")

    changed_bits,_ = bit_changes("ciphertext_orig.txt", "ciphertext_altered.txt")

    os.remove("ciphertext_orig.txt")
    os.remove("altered_plaintext.txt")
    os.remove("ciphertext_altered.txt")

    return changed_bits


def confusion(inputfile):
    """ 
	Performs DES before the key is altered. 
	Then one bit in the key is altered.
	The new key is then written to a file.
	DES is performed again with the altered key.
	The two cipher texts are then compared.
    """
    DES(inputfile, "ciphertext_orig.txt")
    orig_key_bits = file_as_bits("key.txt")
    bit_to_change = random.randrange(orig_key_bits.length())
    orig_key_bits[bit_to_change] ^= 1
    os.remove("key.txt")

    FILEOUT = open("key.txt", 'wb')
    orig_key_bits.write_to_file(FILEOUT)
    FILEOUT.close()

    DES(inputfile, "ciphertext_altered.txt")

    changed_bits, num_blocks = bit_changes("ciphertext_orig.txt", "ciphertext_altered.txt")

    os.remove("ciphertext_orig.txt")
    os.remove("ciphertext_altered.txt")

    return changed_bits / num_blocks


if __name__ == '__main__':
  
   # Problem 1
    avg_bits_changed = []
    for _ in range(20):
    	bits_changed = diffusion("message.txt")
	avg_bits_changed.append(bits_changed)
	#print(bits_changed)
    print(sum(avg_bits_changed) / len(avg_bits_changed))

    # Problem 2
    sbox1 = populate_sboxes()
    sbox2 = populate_sboxes()
    avg_bits_changed = []
    results = []
    for sbox in [sbox1, sbox2]:
	for _ in range(20):
    		bits_changed = diffusion("message.txt", sbox)
		avg_bits_changed.append(bits_changed)
    	avg = sum(avg_bits_changed) / len(avg_bits_changed)
    	results.append(avg)
    print(results[0], results[1])
  
    # Problem 3
    total = 0
    for key in ["ecepurdu", "direwolf", 'oldmaner', 'abcdefgh']:
        os.remove("key.txt")
        with open("key.txt", 'w') as f:
            f.write(key)

        bits_changed = confusion("message.txt")
	total += bits_changed
    print (total / 4)

    '''
        Problem 1:

            Average bits changed: 32

        Problem 2:

            For Random Sbox Generation 1:
               
                Average bits changed: 30

            For Random Sbox Generation 2:
                
                Average bits changed: 31
	    
	    Total Average: 30.5

        Problem 3:

        	Average bits changed: 31
    '''
