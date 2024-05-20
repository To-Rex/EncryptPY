import base64
import hashlib
import struct
import urllib.parse


class TEA:
    TIMES = 32
    DELTA = 0x9e3779b9
    BYTES = b'hicomtea'

    @staticmethod
    def byte2uint(bs):
        return [struct.unpack('<I', bs[i:i + 4])[0] for i in range(0, len(bs), 4)]

    @staticmethod
    def uint2byte(uint):
        return b''.join(struct.pack('<I', val) for val in uint)

    @staticmethod
    def int2uint(v):
        return v & 0xffffffff

    @staticmethod
    def uintAdd(l):
        return l & 0xffffffff

    @staticmethod
    def uintSub(l, sub):
        return (l - sub) & 0xffffffff

    @staticmethod
    def uintLeft(l, offset):
        return ((l << offset) & 0xffffffff)

    @staticmethod
    def uintRight(l, offset):
        return (l >> offset)

    @staticmethod
    def encrypt(bs, keys, delta):
        sum_ = 0
        v = TEA.byte2uint(bs)
        for _ in range(TEA.TIMES):
            sum_ = TEA.uintAdd(sum_ + delta)
            v[0] = TEA.uintAdd(v[0] + (
                TEA.uintAdd(TEA.uintLeft(v[1], 6) + keys[0]) ^ TEA.uintAdd(v[1] + sum_) ^ TEA.uintAdd(
                    TEA.uintRight(v[1], 3) + keys[1])))
            v[1] = TEA.uintAdd(v[1] + (
                TEA.uintAdd(TEA.uintLeft(v[0], 6) + keys[2]) ^ TEA.uintAdd(v[0] + sum_) ^ TEA.uintAdd(
                    TEA.uintRight(v[0], 3) + keys[3])))
        return TEA.uint2byte(v)

    @staticmethod
    def decrypt(bs, keys, delta, sum_):
        v = TEA.byte2uint(bs)
        for _ in range(TEA.TIMES):
            v[1] = TEA.uintSub(v[1],
                               TEA.uintAdd(TEA.uintLeft(v[0], 6) + keys[2]) ^ TEA.uintAdd(v[0] + sum_) ^ TEA.uintAdd(
                                   TEA.uintRight(v[0], 3) + keys[3]))
            v[0] = TEA.uintSub(v[0],
                               TEA.uintAdd(TEA.uintLeft(v[1], 6) + keys[0]) ^ TEA.uintAdd(v[1] + sum_) ^ TEA.uintAdd(
                                   TEA.uintRight(v[1], 3) + keys[1]))
            sum_ = TEA.uintSub(sum_, delta)
        return TEA.uint2byte(v)

    @staticmethod
    def ubyteLeft(v, offset):
        return (v << offset) & 0xff

    @staticmethod
    def ubyteRight(v, offset):
        return (v >> offset) & 0xff

    @staticmethod
    def ubyteAdd(v):
        return v & 0xff

    @staticmethod
    def ubyteSub(v, sub):
        return (v - sub) & 0xff

    @staticmethod
    def encryptByte(b, keys, index):
        m = TEA.BYTES[index % 8] & 0xff
        k = keys[index % 4] & 0xff
        s = b & 0xff
        for _ in range(TEA.TIMES):
            s = TEA.ubyteAdd(s + (TEA.ubyteAdd(TEA.ubyteLeft(m, 3) + k) ^ TEA.ubyteAdd(TEA.ubyteRight(m, 2) + k)))
        return s

    @staticmethod
    def decryptByte(b, keys, index):
        m = TEA.BYTES[index % 8] & 0xff
        k = keys[index % 4] & 0xff
        s = b & 0xff
        for _ in range(TEA.TIMES):
            s = TEA.ubyteSub(s, TEA.ubyteAdd(TEA.ubyteLeft(m, 3) + k) ^ TEA.ubyteAdd(TEA.ubyteRight(m, 2) + k))
        return s

    @staticmethod
    def encrypt_data(bs, key, is_base64):
        if bs is None or key is None or len(key) != 16:
            return None

        len_bs = len(bs)
        remain = len_bs % 8
        align = len_bs - remain
        keys = TEA.byte2uint(key)
        delta = TEA.int2uint(TEA.DELTA)

        encrypted_bs = bytearray(bs)

        for i in range(0, align, 8):
            tmp = bs[i:i + 8]
            encrypted_bs[i:i + 8] = TEA.encrypt(tmp, keys, delta)

        for i in range(align, len_bs):
            encrypted_bs[i] = TEA.encryptByte(bs[i], keys, i)

        if is_base64:
            return base64.b64encode(encrypted_bs).decode()
        else:
            return encrypted_bs

    @staticmethod
    def decrypt_data(bs, key, is_base64):
        if bs is None or len(key) != 16:
            return None

        if is_base64:
            bs = base64.b64decode(bs)

        len_bs = len(bs)
        remain = len_bs % 8
        align = len_bs - remain
        delta = TEA.int2uint(TEA.DELTA)
        keys = TEA.byte2uint(key)
        sum_ = TEA.uintAdd(TEA.TIMES * delta)

        decrypted_bs = bytearray(bs)

        for i in range(0, align, 8):
            tmp = bs[i:i + 8]
            decrypted_bs[i:i + 8] = TEA.decrypt(tmp, keys, delta, sum_)

        for i in range(align, len_bs):
            decrypted_bs[i] = TEA.decryptByte(bs[i], keys, i)

        return decrypted_bs

    @staticmethod
    def encrypt_tea(data, key):
        encrypted_bytes = TEA.encrypt_data(data.encode(), key.encode(), True)
        return encrypted_bytes

    @staticmethod
    def decrypt_tea(data, key):
        decrypted_bytes = TEA.decrypt_data(data, key.encode(), True)
        return decrypted_bytes.decode()

    @staticmethod
    def md5(s):
        return hashlib.md5(s.encode()).hexdigest()


def decode_base64_url(encoded_str):
    # URL-decode the string
    url_decoded_str = urllib.parse.unquote(encoded_str)

    # Add padding if necessary
    padding_needed = len(url_decoded_str) % 4
    if padding_needed:
        url_decoded_str += '=' * (4 - padding_needed)

    return url_decoded_str


# Example usage
# key = "50UvFayZ2w5u3O9B"
# data = '{"phone": "+998995340313","session":"SX2eafvMG0FPejAMi3U8dNNmA+J+ecCDdOXvzH6jhRk8wD1g5+AmTCG6PoZEukai"}'
# #data = '{"phone": "+998995340313","code":"81940"}'
#
# # Encrypt
# encrypted = TEA.encrypt_tea(data, key)
# print(f"Encrypted: {encrypted}")
#
# # Decrypt
# try:
#     decrypted = TEA.decrypt_tea(
#         'TwXZWWsGG/kgW3FnTKdQ0h8iEaYoC91lFfuAA48DCCWMkuDp87ANrYc03VHp2lCVWZDH4UMzx0+LaCkg/Za2056xgoN+bF2HpuhQFEXehw0MVaGTq+Z/+zvCEDd7T3W7V12awXyp99v1OgfJoaN6Tfl1ZbmmkQyzuNG0lpp1LmCozYRIQrq1qm438wfcZiGRKDayQnzFAxNJIEF+ekqe/MvKd/wi7Wp1F412yp9pdVkNrrMurMuhd75TzWwnR3tMwaNDKM0XPLSpJCLa0R2d',
#         key)
#     print(f"Decrypted: {decrypted}")
# except Exception as e:
#     print(f"Error: {e}")
#
