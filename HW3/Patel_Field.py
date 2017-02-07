#!/usr/bin/env python
__author__ = 'Parth'

# Homework Number: 3
# Name: Parth Patel
# ECN Login: patel344
# Due Date: February 2, 2017

import sys

# Obtain Input From User
while True:
        if sys.version_info[0] == 3:
            n = input("Enter an integer smaller than 50: ")
        else:
            n = raw_input("Enter an integer smaller than 50: ")
        n = int(n)
        if n >= 50:
            print("\nInteger must be less than 50.  Try again.\n")
            continue
        else:
            break

for num in range(1,n):
    mod = n
    x, x_old = 0, 1
    y, y_old = 1, 0

    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y

    if num != 1:
        print("ring")
        sys.exit()

# The smallest finite field is GF(2)
if n < 2:
    print("ring")
else:
    print("field")

