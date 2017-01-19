#!/usr/bin/env python
import time
import sys
from BitVector import *

start = time.time()
if len(sys.argv) is not 3:
    sys.exit('''Needs three command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''decrypted output file ''')

PassPhrase = "Hopes and dreams of a million years"

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )

# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1])
encrypted_bv = BitVector( hexstring = FILEIN.read() )

# Goes through all possible keys and performs decyrption until correct key is found
for permutation in range(2**16):
    key_bv = BitVector(intVal=permutation, size=16)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    # Checks to see if key is correct
    if "someplace" in outputtext:
        print(key_bv)
        print(key_bv.get_text_from_bitvector())

        # Write plaintext to the output file:
        FILEOUT = open(sys.argv[2], 'w')
        FILEOUT.write(outputtext)
        FILEOUT.close()
        print(time.time() - start)
        sys.exit()

# "0001001000010111", 4632 --> correct key in binary and int