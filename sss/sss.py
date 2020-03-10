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
    return b64data.decode('ascii')


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


# in_numbers(numbers, value) returns boolean whether or not value is in array
def in_numbers(numbers, value):
    for n in numbers:
        if n == value:
            return True
    return False


# Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
# created by Shamir's Secret Sharing Algorithm requiring a minimum number of
# share to recreate, of length shares, from the input secret raw as a string.
def create(minimum, shares, secret, is_base64):
    result = []
    if minimum > shares:
        raise Exception('cannot require more shares then existing')
    # Convert the secrets to its respective 256-bit Int representation.
    secrets = split_secret_to_int(secret)

    # List of currently used numbers in the polynomial
    numbers = [0]

    # Create the polynomial of degree (minimum - 1); that is, the highest
    # order term is (minimum-1), though as there is a constant term with
    # order 0, there are (minimum) number of coefficients.
    #
    # However, the polynomial object is a 2d array, because we are constructing
    # a different polynomial for each part of the secrets.
    #
    # polynomial[parts][minimum]
    polynomial = [[0] * minimum] * len(secrets)
    print(polynomial)
    for i in range(len(polynomial)):
        polynomial[i][0] = secrets[i]
        for j in range(len(polynomial[i])):
            if j > 0:
                # Each coefficient should be unique
                number = random_number()
                while in_numbers(numbers, number):
                    number = random_number()
                numbers.append(number)

                polynomial[i][j] = number

    # Create the points object; this holds the (x, y) points of each share.
    # Again, because secrets is an array, each share could have multiple parts
    # over which we are computing Shamir's Algorithm. The last dimension is
    # always two, as it is storing an x, y pair of points.
    #
    # Note: this array is technically unnecessary due to creating result
    # in the inner loop. Can disappear later if desired.
    #
    # points[shares][parts][2]
    points = [[[0] * 2] * len(secrets)] * shares
    print(points)
    for i in range(len(points)):
        s = ""
        for j in range(len(points[i])):
            # generate a new x-coordinate.
            number = random_number()
            while in_numbers(numbers, number):
                number = random_number()
            numbers.append(number)

            # and evaluate the polynomial at that point.
            points[i][j][0] = number
            points[i][j][1] = evaluate_polynomial(polynomial[j], number)

            # add it to results.
            if is_base64:
                s += to_base64(points[i][j][0])
                s += to_base64(points[i][j][1])
            else:
                s += to_hex(points[i][j][0])
                s += to_hex(points[i][j][1])
        result.append(s)
    return result


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
    # print(b64data)  # lOpFwywpCeVAcK0/LOKG+YtW71xyj1bX06CcW7VZMFc=
    # hexdata = to_hex(number)
    # print(len(hexdata))  # 64
    # print(hexdata)  # 94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057
    # # decode
    # numb64decode = from_base64(b64data)
    # print(numb64decode)
    # numhexdecode = from_hex(hexdata)
    # print(numhexdecode)

    # # 4. split & merge
    # s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    # print(s)
    # arr = split_secret_to_int(s)
    # print(arr)
    # print(in_numbers(arr, 49937119214509114343548691117920141602615245118674498473442528546336026425464))
    # rs = merge_int_to_string(arr)
    # print(rs)

    # 5. create
    # creates a set of shares
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    arr = create(3, 6, s, False)
    print(arr)

