"""
@author nghiatc
@since Mar 9, 2020
"""

import random
import sys
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

PRIME = 115792089237316195423570985008687907853269984665640564039457584007913129639747


# Returns a random number from the range (0, PRIME-1) inclusive
def random_number():
    rs = random.getrandbits(256)
    while rs >= PRIME:
        rs = random.getrandbits(256)
    return rs


# extended gcd
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


# Computes the multiplicative inverse of the number on the field PRIME.
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# Returns the Int number base10 in base64 representation; note: this is
# not a string representation; the base64 output is exactly 256 bits long.
def to_base64(number):
    numbyte = number.to_bytes(32, 'big')
    b64data = b64encode(numbyte)
    return b64data


# Returns the Int number base10 in Hex representation; note: this is
# not a string representation; the Hex output is exactly 256 bits long.
def to_hex(number):
    numbyte = number.to_bytes(32, 'big')
    hexdata = hexlify(numbyte).decode('ascii')
    return hexdata


if __name__ == '__main__':
    # # 1. random_number
    # for i in range(100):
    #     rd = random_number()
    #     print("rd", rd)

    # # 2. modinv
    # # v = modinv(42, 2017)  # 1969
    # a = 67356225285819719212258382314594931188352598651646313425411610888829358649431
    # v = modinv(a, PRIME)
    # print(v)
    # # 66304286696287781344919781629879750902445808730247479812988635671630372079315
    # print((a * v) % PRIME)
    # # 1

    # 3. to_base64
    # number = 2020
    number = 67356225285819719212258382314594931188352598651646313425411610888829358649431
    print(to_base64(number))
    hexdata = to_hex(number)
    print(len(hexdata))
    print(hexdata)
