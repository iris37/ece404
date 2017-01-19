#!/usr/bin/env python

import string
import sys


def vignere_encrypt(plaintext):
    with open(plaintext) as f:
        orig_text = f.readlines()[0]

    circ_buffer = list(string.ascii_letters)
    cipher_text = ""

    # Get key from user:
    key = None
    if sys.version_info[0] == 3:
        key = input("\nEnter key: ")
    else:
        key = raw_input("\nEnter key: ")
    key = key.strip()

    for i in range(len(orig_text)):
        key_index = circ_buffer.index(key[i % len(key)])       # gets index of key character in buffer
        orig_index = circ_buffer.index(orig_text[i])           # gets index of current text char
        cipher_text += circ_buffer[((key_index + orig_index) % len(circ_buffer))]  # encrypts character

    with open('ciphertext_v.txt', 'w') as f:
        f.write(cipher_text)
    return


def vignere_decrypt(filename):
    """Test Decrypt Function to Check if Vignere encryption occured correctly"""

    with open(filename) as f:
        cipher_text = f.readlines()[0]

    circ_buffer = list(string.ascii_letters)
    plain_text = ""

    # Get key from user:
    key = None
    if sys.version_info[0] == 3:
        key = input("\nEnter key: ")
    else:
        key = raw_input("\nEnter key: ")
    key = key.strip()

    for i in range(len(cipher_text)):
        key_index = circ_buffer.index(key[i % len(key)])
        orig_index = circ_buffer.index(cipher_text[i])
        plain_text += circ_buffer[orig_index - key_index]  # Don't need to mod bc python will automatically loop

    print(plain_text)
    with open('plaintext_v.txt', 'w') as f:
        f.write(plain_text)
    return

if __name__ == '__main__':
    vignere_encrypt('plaintext.txt')   # User needs to create a file called 'plaintext.txt'
    vignere_decrypt('ciphertext_v.txt')