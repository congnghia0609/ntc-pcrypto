import unittest

from sss.sss import *


class TestSSS(unittest.TestCase):
    def test_encode_decode_hex(self):
        number = 67356225285819719212258382314594931188352598651646313425411610888829358649431
        # print(number)
        # encode
        hex_data = to_hex(number)
        # print(len(hex_data))  # 64
        # print(hex_data)  # 94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057
        # decode
        hex_decode = from_hex(hex_data)
        # print(hex_decode)
        self.assertEqual(number, hex_decode)

    def test_encode_decode_base64url(self):
        number = 67356225285819719212258382314594931188352598651646313425411610888829358649431
        # print(number)
        # encode
        b64data = to_base64(number)
        # print(len(b64data))  # 44
        # print(b64data)  # lOpFwywpCeVAcK0_LOKG-YtW71xyj1bX06CcW7VZMFc=
        # decode
        numb64decode = from_base64(b64data)
        # print(numb64decode)
        self.assertEqual(number, numb64decode)

    def test_split_merge(self):
        s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        arr = split_secret_to_int(s)
        rs = merge_int_to_string(arr)
        self.assertEqual(rs, s)

    def test_full_base64url(self):
        s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        # creates a set of shares
        arr = create(3, 6, s, True)

        # combines shares into secret
        s1 = combine(arr[:3], True)
        self.assertEqual(s1, s)

        s2 = combine(arr[3:], True)
        self.assertEqual(s2, s)

        s3 = combine(arr[1:5], True)
        self.assertEqual(s3, s)

    def test_full_hex(self):
        s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        # creates a set of shares
        arr = create(3, 6, s, False)

        # combines shares into secret
        s1 = combine(arr[:3], False)
        self.assertEqual(s1, s)

        s2 = combine(arr[3:], False)
        self.assertEqual(s2, s)

        s3 = combine(arr[1:5], False)
        self.assertEqual(s3, s)

    # Test create & combine Base64Url with special cases not Latin symbols
    def test_full_base64url_with_special_cases(self):
        s = "бар"  # Cyrillic
        # creates a set of shares
        arr = create(3, 6, s, True)

        # combines shares into secret
        s1 = combine(arr[:3], True)
        self.assertEqual(s1, s)

        s2 = combine(arr[3:], True)
        self.assertEqual(s2, s)

        s3 = combine(arr[1:5], True)
        self.assertEqual(s3, s)

    # Test create & combine Hex with special cases not Latin symbols
    def test_full_hex_with_special_cases(self):
        s = "бар"  # Cyrillic
        # creates a set of shares
        arr = create(3, 6, s, False)

        # combines shares into secret
        s1 = combine(arr[:3], False)
        self.assertEqual(s1, s)

        s2 = combine(arr[3:], False)
        self.assertEqual(s2, s)

        s3 = combine(arr[1:5], False)
        self.assertEqual(s3, s)


if __name__ == '__main__':
    unittest.main()
