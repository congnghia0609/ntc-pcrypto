"""
@author nghiatc
@since Mar 9, 2020
"""
import math
import random
from binascii import hexlify, unhexlify
from base64 import urlsafe_b64encode, urlsafe_b64decode

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
    b64data = urlsafe_b64encode(numbyte)
    return b64data.decode('ascii')


# Returns the number base64 in base 10 Int representation; note: this is
# not coming from a string representation; the base64 input is exactly 256
# bits long, and the output is an arbitrary size base 10 integer.
def from_base64(number):
    numbyte = urlsafe_b64decode(number)
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
def evaluate_polynomial(polynomial, part, value):
    last = len(polynomial[part]) - 1
    result = polynomial[part][last]
    s = last - 1
    while s >= 0:
        result = (result * value + polynomial[part][s]) % PRIME
        s = s - 1
    return result


# Converts a byte array into an a 256-bit Int, array based upon size of
# the input byte; all values are right-padded to length 256, even if the most
# significant bit is zero.
def split_secret_to_int(secret):
    result = []
    hex_data = hexlify(secret.encode('ascii')).decode('ascii')  # "".join("{:02x}".format(ord(c)) for c in secret)
    count = math.ceil(len(hex_data) / 64.0)
    i = 0
    while i < count:
        if (i + 1) * 64 < len(hex_data):
            subs = hex_data[i * 64:(i + 1) * 64]
            result.append(int(subs, 16))
        else:
            last = hex_data[i * 64:len(hex_data)]
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
    byte_data = unhexlify(hex_data).decode('ascii').rstrip('\x00')
    return byte_data


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

    # Verify minimum isn't greater than shares; there is no way to recreate
    # the original polynomial in our current setup, therefore it doesn't make
    # sense to generate fewer shares than are needed to reconstruct the secrets.
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
    # https://www.geeksforgeeks.org/python-using-2d-arrays-lists-the-right-way/
    polynomial = [[0 for i in range(minimum)] for j in range(len(secrets))]
    for i in range(len(secrets)):
        polynomial[i][0] = secrets[i]
        j = 1
        while j < minimum:
            # Each coefficient should be unique
            number = random_number()
            while in_numbers(numbers, number):
                number = random_number()
            numbers.append(number)

            polynomial[i][j] = number
            j = j + 1

    # Create the points object; this holds the (x, y) points of each share.
    # Again, because secrets is an array, each share could have multiple parts
    # over which we are computing Shamir's Algorithm. The last dimension is
    # always two, as it is storing an x, y pair of points.
    #
    # Note: this array is technically unnecessary due to creating result
    # in the inner loop. Can disappear later if desired.
    #
    # points[shares][parts][2]
    points = [[[0 for i in range(2)] for j in range(len(secrets))] for k in range(shares)]
    # For every share...
    for i in range(shares):
        s = ""
        # and every part of the secrets...
        for j in range(len(secrets)):
            # generate a new x-coordinate.
            number = random_number()
            while in_numbers(numbers, number):
                number = random_number()
            numbers.append(number)

            # and evaluate the polynomial at that point.
            points[i][j][0] = number
            points[i][j][1] = evaluate_polynomial(polynomial, j, number)

            # add it to results.
            if is_base64:
                s += to_base64(points[i][j][0])
                s += to_base64(points[i][j][1])
            else:
                s += to_hex(points[i][j][0])
                s += to_hex(points[i][j][1])
        result.append(s)
    return result


# Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
#     Note: the polynomial will converge if the specified minimum number of shares
#           or more are passed to this function. Passing thus does not affect it
#           Passing fewer however, simply means that the returned secret is wrong.
def combine(shares, is_base64):
    if len(shares) == 0:
        raise Exception('shares is NULL or empty')

    # Recreate the original object of x, y points, based upon number of shares
    # and size of each share (number of parts in the secret).
    #
    # points[shares][parts][2]
    if is_base64:
        points = decode_share_base64(shares)
    else:
        points = decode_share_hex(shares)

    # Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secrets.
    # For each part of the secrets (clearest to iterate over)...
    secrets = [0 for i in range(len(points[0]))]
    for j in range(len(points[0])):
        secrets[j] = 0
        # and every share...
        for i in range(len(points)):  # LPI sum loop
            # remember the current x and y values.
            ax = points[i][j][0]  # ax
            ay = points[i][j][1]  # ay
            numerator = 1  # LPI numerator
            denominator = 1  # LPI denominator
            # and for every other point...
            for k in range(len(points)):  # LPI product loop
                if k != i:
                    # combine them via half products.
                    # x=0 ==> [(0-bx)/(ax-bx)] * ...
                    bx = points[k][j][0]  # bx
                    negbx = -bx  # (0 - bx)
                    axbx = ax - bx  # (ax - bx)

                    numerator = (numerator * negbx) % PRIME  # (0 - bx) * ...
                    denominator = (denominator * axbx) % PRIME  # (ax - bx) * ...

            # LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
            # multiply together the points (ay)(numerator)(denominator)^-1 ...
            fx = ay
            fx = (fx * numerator) % PRIME
            fx = (fx * modinv(denominator, PRIME)) % PRIME

            # LPI sum: s = fx + fx + ...
            secrets[j] = (secrets[j] + fx) % PRIME
    return merge_int_to_string(secrets)


# Takes a string array of shares encoded in Base64 created via Shamir's
# Algorithm; each string must be of equal length of a multiple of 88 characters
# as a single 88 character share is a pair of 256-bit numbers (x, y).
def decode_share_base64(shares):
    # Recreate the original object of x, y points, based upon number of shares
    # and size of each share (number of parts in the secret).
    secrets = [0] * len(shares)

    # For each share...
    for i in range(len(shares)):
        # ensure that it is valid.
        if not is_valid_share_base64(shares[i]):
            raise Exception('one of the shares is invalid')

        # find the number of parts it represents.
        share = shares[i]
        count = (int)(len(share) / 88)
        secrets[i] = [0] * count

        # and for each part, find the x,y pair...
        for j in range(count):
            cshare = share[j * 88:(j + 1) * 88]
            secrets[i][j] = [0] * 2
            # decoding from Base64.
            secrets[i][j][0] = from_base64(cshare[0:44])
            secrets[i][j][1] = from_base64(cshare[44:])
    return secrets


# akes a string array of shares encoded in Hex created via Shamir's
# Algorithm; each string must be of equal length of a multiple of 128 characters
# as a single 128 character share is a pair of 256-bit numbers (x, y).
def decode_share_hex(shares):
    # Recreate the original object of x, y points, based upon number of shares
    # and size of each share (number of parts in the secret).
    secrets = [0] * len(shares)

    # For each share...
    for i in range(len(shares)):
        # ensure that it is valid.
        if not is_valid_share_hex(shares[i]):
            raise Exception('one of the shares is invalid')

        # find the number of parts it represents.
        share = shares[i]
        count = (int)(len(share) / 128)
        secrets[i] = [0] * count

        # and for each part, find the x,y pair...
        for j in range(count):
            cshare = share[j * 128:(j + 1) * 128]
            secrets[i][j] = [0] * 2
            # decoding from Base64.
            secrets[i][j][0] = from_hex(cshare[0:64])
            secrets[i][j][1] = from_hex(cshare[64:])
    return secrets


# Takes in a given string to check if it is a valid secret
#
# Requirements:
#   Length multiple of 88
#   Can decode each 44 character block as Base64
#
# Returns only success/failure (bool)
def is_valid_share_base64(candidate):
    if len(candidate) == 0 or len(candidate) % 88 != 0:
        return False
    count = len(candidate) / 44
    j = 0
    while j < count:
        part = candidate[j * 44:(j + 1) * 44]
        decode = from_base64(part)
        if decode <= 0 or decode >= PRIME:
            return False
        j = j + 1
    return True


# Takes in a given string to check if it is a valid secret
#
# Requirements:
#  	Length multiple of 128
# 	Can decode each 64 character block as Hex
#
# Returns only success/failure (bool)
def is_valid_share_hex(candidate):
    if len(candidate) == 0 or len(candidate) % 128 != 0:
        return False
    count = len(candidate) / 64
    j = 0
    while j < count:
        part = candidate[j * 64:(j + 1) * 64]
        decode = from_hex(part)
        if decode <= 0 or decode >= PRIME:
            return False
        j = j + 1
    return True
