from typing import Tuple, Optional, Any
import hashlib
import binascii

# Set DEBUG to True to get a detailed debug output including
# intermediate values during key generation, signing, and
# verification. This is implemented via calls to the
# debug_print_vars() function.
#
# If you want to print values on an individual basis, use
# the pretty() function, e.g., print(pretty(foo)).
DEBUG = False

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

def lift_x(x: int) -> Optional[Point]:
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else p-y)

def point_negate(P: Optional[Point]) -> Optional[Point]:
    if P is None:
        return P
    return (x(P), p - y(P))

def cpoint(x: bytes) -> Point:
    if len(x) != 33:
        raise ValueError('x is not a valid compressed point.')
    P = lift_x(int_from_bytes(x[1:33]))
    if P is None:
        raise ValueError('x is not a valid compressed point.')
    if x[0] == 2:
        return P
    elif x[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else:
        raise ValueError('x is not a valid compressed point.')

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0

def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

def parity_from_point(P: Point) -> bytes:
    assert not is_infinite(P)
    return b"\x02" if has_even_y(P) else b"\x03"

def schnorr_pre_sign(msg: bytes, seckey: bytes, aux_rand: bytes, T: bytes) -> bytes:
    d0 = int_from_bytes(seckey) #private key
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, d0) #public key
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    if len(T) != 33:
        raise ValueError('T must be a compressed point (33 bytes) instead of %i.' % len(T))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + T + bytes_from_point(P) + msg)) % n #nonce r
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0) # elliptic curve point R=rG
    assert R is not None
    T = cpoint(T)
    R0 = point_add(R, T) # elliptic curve point R0 = R + T
    k = n - k0 if not has_even_y(R0) else k0
    if is_infinite(R0):
        raise RuntimeError('Failure. This happens only with negligible probability.')
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R0) + bytes_from_point(P) + msg)) % n
    sig = parity_from_point(R0) + bytes_from_point(R0) + bytes_from_int((k + e * d) % n)
    debug_print_vars()
    if not schnorr_pre_verify(msg, T, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_pre_verify(msg: bytes, T: Point, pubkey: bytes, pre_sig: bytes) -> bool:
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(pre_sig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    T0 = schnorr_adaptor_extract_t(msg, pubkey, pre_sig)
    if (T0 is None) or (T0 is False):
        debug_print_vars()
        return False
    return T0 == T

def schnorr_adaptor_extract_t(msg: bytes, pubkey: bytes, sig: bytes) -> Optional[Point]:
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    P = lift_x(int_from_bytes(pubkey))
    s0 = int_from_bytes(sig[33:65])
    if (P is None) or (s0 >= n):
        debug_print_vars()
        return False
    R0 = lift_x(int_from_bytes(sig[1:33]))
    if R0 is None:
        debug_print_vars()
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[1:33] + bytes_from_point(P) + msg)) % n
    R = point_add(point_mul(G, s0), point_mul(P, n - e))
    if (R is None):
        debug_print_vars()
        return False
    T = point_add(R0, point_negate(R))
    if sig[0] == 2:
        pass
    elif sig[0] == 3:
        T = point_negate(T)
    else:
        raise ValueError('The signature must start with 0x02 or 0x03.')
    if (T is None):
        debug_print_vars()
        return False
    return T

def schnorr_adapt(sig: bytes, adaptor: bytes) -> bytes:
    if len(sig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    s0 = int_from_bytes(sig[33:65])
    t = int_from_bytes(adaptor)
    if (s0 >= n) or (t >= n):
        debug_print_vars()
        raise ValueError('The signature and adaptor must be an integer in the range 1..n-1')
    if sig[0] == 2:
        s = (s0 + t) % n
    elif sig[0] == 3:
        s = (s0 - t) % n
    sig64 = sig[1:33] + bytes_from_int(s)
    return sig64

def schnorr_extract_adaptor(sig65: bytes, sig64: bytes) -> bytes:
    if len(sig65) != 65:
        raise ValueError('The adaptor signature must be a 65-byte array.')
    if len(sig64) != 64:
        raise ValueError('The adaptor signature must be a 64-byte array.')
    s0 = int_from_bytes(sig65[33:65])
    s = int_from_bytes(sig64[32:64])
    if (s0 >= n) or (s >= n):
        debug_print_vars()
        raise ValueError('The signatures must be an integer in the range 1..n-1')
    if sig65[0] == 2:
        t = bytes_from_int((s - s0) % n)
    elif sig65[0] == 3:
        t = bytes_from_int((s0 - s) % n)
    return t

#
# Debugging functions
#
import inspect

def pretty(v: Any) -> Any:
    if isinstance(v, bytes):
        return '0x' + v.hex()
    if isinstance(v, int):
        return pretty(bytes_from_int(v))
    if isinstance(v, tuple):
        return tuple(map(pretty, v))
    return v

def debug_print_vars() -> None:
    if DEBUG:
        current_frame = inspect.currentframe()
        assert current_frame is not None
        frame = current_frame.f_back
        assert frame is not None
        print('   Variables in function ', frame.f_code.co_name, ' at line ', frame.f_lineno, ':', sep='')
        for var_name, var_val in frame.f_locals.items():
            print('   ' + var_name.rjust(11, ' '), '==', pretty(var_val))

#
# The following code is only used to verify the test vectors.
#
import csv
import os
import sys

def test_vectors() -> bool:
    all_passed = True
    with open(os.path.join(sys.path[0], 'test_vectors.csv'), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, T_hex, t_hex, sig_hex, sig64_hex, test_type_str, result_str, comment) = row
            sig = bytes.fromhex(sig_hex)
            result = result_str == 'TRUE'
            print('\nTest vector', ('#' + index).rjust(3, ' ') + ':')
            if seckey_hex != '':
                pubkey = bytes.fromhex(pubkey_hex)
                msg = bytes.fromhex(msg_hex)
                seckey = bytes.fromhex(seckey_hex)
                pubkey_actual = pubkey_gen(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                aux_rand = bytes.fromhex(aux_rand_hex)
                T = bytes.fromhex(T_hex)
                try:
                    sig_actual = schnorr_pre_sign(msg, seckey, aux_rand, T)
                    if sig == sig_actual:
                        print(' * Passed signing test.')
                    else:
                        print(' * Failed signing test.')
                        print('   Expected signature:', sig.hex().upper())
                        print('     Actual signature:', sig_actual.hex().upper())
                        all_passed = False
                except RuntimeError as e:
                    print(' * Signing test raised exception:', e)
                    all_passed = False
            if pubkey_hex != '' and msg_hex != '':
                pubkey = bytes.fromhex(pubkey_hex)
                msg = bytes.fromhex(msg_hex)
                T = cpoint(bytes.fromhex(T_hex))
                result_actual = schnorr_pre_verify(msg, T, pubkey, sig)
                if result == result_actual:
                    print(' * Passed verification test.')
                else:
                    print(' * Failed verification test.')
                    print('   Expected verification result:', result)
                    print('     Actual verification result:', result_actual)
                    if comment:
                        print('   Comment:', comment)
                    all_passed = False
            if sig64_hex != '' and t_hex != '':
                sig64 = bytes.fromhex(sig64_hex)
                t = bytes.fromhex(t_hex)
                if test_type_str == "" or "Adaptor extraction" in test_type_str:
                    adaptor = schnorr_extract_adaptor(sig, sig64)
                    result_actual = t == adaptor
                    if result == result_actual:
                        print(' * Passed adaptor extraction test.')
                    else:
                        print(' * Failed adaptor extraction test.')
                        print('   Expected adaptor:', t.hex().upper())
                        print('     Actual adaptor:', adaptor.hex().upper())
                        if comment:
                            print('   Comment:', comment)
                        all_passed = False
                if test_type_str == "" or "Adapting" in test_type_str:
                    sig_actual = schnorr_adapt(sig, t)
                    result_actual = sig64 == sig_actual
                    if result == result_actual:
                        print(' * Passed adapting test.')
                    else:
                        print(' * Failed adapting test.')
                        print('   Expected adapted schnorr signature:', sig64.hex().upper())
                        print('     Actual adapted schnorr signature:', sig_actual.hex().upper())
                        if comment:
                            print('   Comment:', comment)
                        all_passed = False
    print()
    if all_passed:
        print('All test vectors passed.')
    else:
        print('Some test vectors failed.')
    return all_passed

# Helper Functions

import os

def generate_aux_rand() -> bytes:
    return os.urandom(32)

def message_encode_32bytes(msg: str) -> bytes:
    return hashlib.sha256(msg.encode()).digest()

def point_from_hex(p: tuple) -> Point:
    x = int_from_bytes(bytes.fromhex(p[0]))
    y = int_from_bytes(bytes.fromhex(p[1]))
    return (x, y)

def compress_point(P: Point) -> bytes:
    return parity_from_point(P) + bytes_from_point(P)

def test_pre_sign_generation() -> bool:
    print("Test for generating a schnorr adaptor signature.")
    msg = message_encode_32bytes("test")
    print("msg:  " + msg.hex())
    seckey = bytes_from_int(1)
    print("seckey:  " + seckey.hex())
    aux_rand = generate_aux_rand()
    print("aux_rand:  " + aux_rand.hex())
    t = 2
    print("t:  " + bytes_from_int(t).hex())
    T = compress_point(point_mul(G, t))
    assert T is not None
    print("T:  " + T.hex())
    sig = schnorr_pre_sign(msg, seckey, aux_rand, T)
    print("sig:  " + sig.hex())
    print("sig_parity:  " + sig[0:1].hex())
    print("sig_R:  " + sig[1:33].hex())
    print(has_even_y(cpoint(sig[0:33])))
    print("sig_sig:  " + sig[33:65].hex())
    sig64 = schnorr_adapt(sig, bytes_from_int(t))
    print("sig64:  " + sig64.hex())
    t1 = schnorr_extract_adaptor(sig, sig64)
    assert t == int_from_bytes(t1)
    return True

def test_pre_sign_nonce() -> bool:
    print("Test for nonce generation")
    print()
    msg = message_encode_32bytes("test")
    print("msg:  " + msg.hex())
    seckey = bytes_from_int(1)
    print("seckey:  " + seckey.hex())
    aux_rand = generate_aux_rand()
    print("aux_rand:  " + aux_rand.hex())
    T = compress_point((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B7))
    assert T is not None
    print("T:  " + T.hex())
    sig = schnorr_pre_sign(msg, seckey, aux_rand, T)
    print("sig:  " + sig.hex())
    print("sig_parity:  " + sig[0:1].hex())
    print("sig_R:  " + sig[1:33].hex())
    print(has_even_y(cpoint(sig[0:33])))
    print("sig_sig:  " + sig[33:65].hex())
    return True

def test_pre_sign_nonce_without_auxrand() -> bool:
    print("Test for nonce generation without a random auxrand.")

    print()
    print("Test with different T")
    msg = message_encode_32bytes("test")
    print("msg:  " + msg.hex())
    seckey = bytes_from_int(1)
    aux_rand = bytes_from_int(1)
    t1 = 2
    T1 = compress_point(point_mul(G, t1))
    assert T1 is not None
    print("T1:  " + T1.hex())
    sig1 = schnorr_pre_sign(msg, seckey, aux_rand, T1)
    print("sig1_parity:  " + sig1[0:1].hex())
    print("sig1_R:  " + sig1[1:33].hex())
    print(has_even_y(cpoint(sig1[0:33])))
    print("sig1_sig:  " + sig1[33:65].hex())
    sig164 = schnorr_adapt(sig1, bytes_from_int(t1))
    print("sig1_64:  " + sig164.hex())
    t11 = schnorr_extract_adaptor(sig1, sig164)
    assert t1 == int_from_bytes(t11)

    t2 = 5
    T2 = compress_point(point_mul(G, t2))
    assert T2 is not None
    print("T2:  " + T2.hex())
    sig2 = schnorr_pre_sign(msg, seckey, aux_rand, T2)
    print("sig2_parity:  " + sig2[0:1].hex())
    print("sig2_R:  " + sig2[1:33].hex())
    print(has_even_y(cpoint(sig2[0:33])))
    print("sig2_sig:  " + sig2[33:65].hex())
    sig264 = schnorr_adapt(sig2, bytes_from_int(t2))
    print("sig2_64:  " + sig264.hex())
    t21 = schnorr_extract_adaptor(sig2, sig264)
    assert t2 == int_from_bytes(t21)

    print()
    print("Test with different seckey")
    print("seckey1:  " + seckey.hex())
    seckey2 = bytes_from_int(2)
    print("seckey2:  " + seckey2.hex())
    sig3 = schnorr_pre_sign(msg, seckey2, aux_rand, T1)
    print("sig1_parity:  " + sig1[0:1].hex())
    print("sig1_R:  " + sig1[1:33].hex())
    print(has_even_y(cpoint(sig1[0:33])))
    print("sig1_sig:  " + sig1[33:65].hex())
    print("sig2_parity:  " + sig3[0:1].hex())
    print("sig2_R:  " + sig3[1:33].hex())
    print(has_even_y(cpoint(sig3[0:33])))
    print("sig2_sig:  " + sig3[33:65].hex())
    sig364 = schnorr_adapt(sig3, bytes_from_int(t1))
    print("sig2_64:  " + sig364.hex())
    t31 = schnorr_extract_adaptor(sig3, sig364)
    assert t1 == int_from_bytes(t31)

    print()
    print("Test with different msg")
    print("msg1:  " + msg.hex())
    msg2 = message_encode_32bytes("test2")
    print("msg2:  " + msg2.hex())
    sig4 = schnorr_pre_sign(msg2, seckey, aux_rand, T1)
    print("sig1_parity:  " + sig1[0:1].hex())
    print("sig1_R:  " + sig1[1:33].hex())
    print(has_even_y(cpoint(sig1[0:33])))
    print("sig1_sig:  " + sig1[33:65].hex())
    print("sig2_parity:  " + sig4[0:1].hex())
    print("sig2_R:  " + sig4[1:33].hex())
    print(has_even_y(cpoint(sig4[0:33])))
    print("sig2_sig:  " + sig4[33:65].hex())
    sig464 = schnorr_adapt(sig4, bytes_from_int(t1))
    print("sig2_64:  " + sig464.hex())
    t41 = schnorr_extract_adaptor(sig4, sig464)
    assert t1 == int_from_bytes(t41)

if __name__ == "__main__":
    test_pre_sign_generation()
    print()
    test_pre_sign_nonce()
    print()
    test_pre_sign_nonce_without_auxrand()
    print()
    test_vectors()
