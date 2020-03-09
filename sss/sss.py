"""
@author nghiatc
@since Mar 9, 2020
"""
import math
import random
import sys
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

# The largest PRIME 256-bit big.Int
# https://primes.utm.edu/lists/2small/200bit.html
# PRIME = 2^n - k = 2^256 - 189
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


# Returns the number base64 in base 10 Int representation; note: this is
# not coming from a string representation; the base64 input is exactly 256
# bits long, and the output is an arbitrary size base 10 integer.
def from_base64(number):
    numbyte = b64decode(number)
    return int.from_bytes(numbyte, 'big')


# Returns the Int number base10 in Hex representation; note: this is
# not a string representation; the Hex output is exactly 256 bits long.
def to_hex(number):
    numbyte = number.to_bytes(32, 'big')
    hexdata = hexlify(numbyte).decode('ascii')
    return hexdata


# Returns the number Hex in base 10 Int representation; note: this is
# not coming from a string representation; the Hex input is exactly 256
# bits long, and the output is an arbitrary size base 10 integer.
def from_hex(number):
    numbyte = unhexlify(number)
    return int.from_bytes(numbyte, 'big')


# Evaluates a polynomial with coefficients specified in reverse order:
#  evaluatePolynomial([a, b, c, d], x):
#  		return a + bx + cx^2 + dx^3
#  Horner's method: ((dx + c)x + b)x + a
def evaluate_polynomial(polynomial, value):
    last = len(polynomial) - 1
    result = polynomial[last]
    s = last - 1
    while s >= 0:
        # result = result.Mul(result, value)
        # result = result.Add(result, polynomial[s])
        # result = result.Mod(result, PRIME)
        result = (result * value + polynomial[s]) % PRIME
        # result = result + polynomial[s]
        # result = result % PRIME
        s = s -1
    return result


# Converts a byte array into an a 256-bit Int, array based upon size of
# the input byte; all values are right-padded to length 256, even if the most
# significant bit is zero.
def split_secret_to_int(secret):
    result = []
    hex_data = "".join("{:02x}".format(ord(c)) for c in secret)
    print(hex_data)
    print(len(hex_data))
    count = math.ceil(len(hex_data) / 64.0)
    print(count)
    i = 0
    while i < count:
        if (i+1)*64 < len(hex_data):
            subs = hex_data[i*64:(i+1)*64]
            result.append(int(subs, 16))
        else:
            last = hex_data[i*64:len(hex_data)]
            n = 64 - len(last)
            j = 0
            while j < n:
                last += "0"
                j = j + 1
            result.append(int(last, 16))
        i = i + 1
    return result


# Converts an array of Ints to the original byte array, removing any
# least significant nulls.
def merge_int_to_string(secrets):
    hex_data = ""
    for s in secrets:
        tmp = to_hex(s)
        hex_data += tmp
    byte_data = unhexlify(hex_data)
    print(byte_data)
    return byte_data.decode('ascii').rstrip('\x00')


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

    # # 3. encode/decode
    # # number = 2020
    # # encode
    # number = 67356225285819719212258382314594931188352598651646313425411610888829358649431
    # print(number)
    # b64data = to_base64(number)
    # print(b64data)  # b'lOpFwywpCeVAcK0/LOKG+YtW71xyj1bX06CcW7VZMFc='
    # hexdata = to_hex(number)
    # print(len(hexdata))  # 64
    # print(hexdata)  # 94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057
    # # decode
    # numb64decode = from_base64(b64data)
    # print(numb64decode)
    # numhexdecode = from_hex(hexdata)
    # print(numhexdecode)

    # 4. split & merge
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print(s)
    arr = split_secret_to_int(s)
    print(arr)
    rs = merge_int_to_string(arr)
    print(rs)
