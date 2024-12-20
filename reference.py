# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import Tuple, Optional, Union, Any, NewType
import hashlib
import secrets

#
# The following helper functions were copied from these reference implementations:
# 1. BIP340: https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
# 2. BIP327: https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#

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
PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

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

def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + xbytes(P)

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
    if P is None: # invalid x-coordinate
        raise ValueError('x is not a valid compressed point.')
    if x[0] == 2:
        return P
    elif x[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else: # invalid parity
        raise ValueError('x is not a valid compressed point.')

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0

def pubkey_gen_xonly(seckey: bytes) -> XonlyPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return XonlyPk(xbytes(P))

def pubkey_gen_plain(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return PlainPk(cbytes(P))

def schnorr_verify(msg: bytes, pubkey: XonlyPk, sig: bytes) -> bool:
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x(int_from_bytes(pubkey))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= p) or (s >= n):
        debug_print_vars()
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)) or (x(R) != r):
        debug_print_vars()
        return False
    debug_print_vars()
    return True

#
# End of helper functions copied from BIP-340 reference implementation.
#
# TODO: fix variable names & add xonly type in relevant args
def schnorr_presig_sign(msg: bytes, seckey: bytes, aux_rand: bytes, T: PlainPk) -> bytes:
    d0 = int_from_bytes(seckey) #private key
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, d0) #public key
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("SchnorrAdaptor/aux", aux_rand))
    if len(T) != 33:
        raise ValueError('T must be a compressed point (33 bytes) instead of %i.' % len(T))
    k0 = int_from_bytes(tagged_hash("SchnorrAdaptor/nonce", t + T + xbytes(P) + msg)) % n #nonce r
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0) # elliptic curve point R=rG
    assert R is not None
    T_point = cpoint(T)
    assert T_point is not None
    R0 = point_add(R, T_point) # elliptic curve point R0 = R + T
    if R0 is None: # fail if point at infinity
        raise RuntimeError('Failure. This happens only with negligible probability.')
    k = n - k0 if not has_even_y(R0) else k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", xbytes(R0) + xbytes(P) + msg)) % n
    sig = cbytes(R0) + bytes_from_int((k + e * d) % n)
    debug_print_vars()
    if not schnorr_presig_verify(msg, T, XonlyPk(xbytes(P)), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_presig_verify(msg: bytes, adaptor: PlainPk, pubkey: XonlyPk, presig: bytes) -> bool:
    if len(adaptor) != 33:
        raise ValueError('The adaptor must be a 33-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(presig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    adaptor_expected = schnorr_extract_adaptor(msg, pubkey, presig)
    if (adaptor_expected is None):
        return False
    return adaptor_expected == adaptor

def schnorr_extract_adaptor(msg: bytes, pubkey: bytes, sig: bytes) -> Optional[PlainPk]:
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    P = lift_x(int_from_bytes(pubkey))
    s0 = int_from_bytes(sig[33:65])
    if (P is None) or (s0 >= n):
        debug_print_vars()
        return None
    try:
        R0 = cpoint(sig[0:33])
    except Exception:
        return None
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[1:33] + xbytes(P) + msg)) % n
    R = point_add(point_mul(G, s0), point_mul(P, n - e))
    if (R is None):
        debug_print_vars()
        return None
    T = point_add(R0, point_negate(R)) if has_even_y(R0) else point_add(R0, R)
    if (T is None):
        debug_print_vars()
        return None
    return PlainPk(cbytes(T))

def schnorr_adapt(sig: bytes, adaptor: bytes) -> bytes:
    if len(sig) != 65:
        raise ValueError('The signature must be a 65-byte array.')
    if sig[0] not in [0x02, 0x03]:
        raise ValueError('The signature must start with 0x02 or 0x03.')
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

def schnorr_extract_secadaptor(sig65: bytes, sig64: bytes) -> bytes:
    if len(sig65) != 65:
        raise ValueError('The adaptor signature must be a 65-byte array.')
    if len(sig64) != 64:
        raise ValueError('The adaptor signature must be a 64-byte array.')
    if sig65[0] not in [0x02, 0x03]:
        raise ValueError('The signature must start with 0x02 or 0x03.')
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

def presig_test_vectors() -> bool:
    all_passed = True
    with open(os.path.join(sys.path[0], 'vectors/presig_vectors.csv'), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, adaptor_hex, presig_hex, result_str, comment) = row
            # ignores the last row which doesn't contain any test vectors
            if index == '':
                continue
            pubkey = XonlyPk(bytes.fromhex(pubkey_hex))
            msg = bytes.fromhex(msg_hex)
            adaptor = PlainPk(bytes.fromhex(adaptor_hex))
            presig = bytes.fromhex(presig_hex)
            result = result_str == 'TRUE'
            print('\nTest vector', ('#' + index).rjust(3, ' ') + ':')
            if seckey_hex != '':
                seckey = bytes.fromhex(seckey_hex)
                pubkey_actual = pubkey_gen_xonly(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                # `aux_rand` won't be a empty string when `seckey` is present
                aux_rand = bytes.fromhex(aux_rand_hex)
                try:
                    presig_actual = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
                    if presig == presig_actual:
                        print(' * Passed signing test.')
                    else:
                        print(' * Failed signing test.')
                        print('   Expected pre-signature:', presig.hex().upper())
                        print('     Actual pre-signature:', presig_actual.hex().upper())
                        all_passed = False
                except RuntimeError as e:
                    print(' * Signing test raised exception:', e)
                    all_passed = False
            result_actual = schnorr_presig_verify(msg, adaptor, pubkey, presig)
            if result == result_actual:
                print(' * Passed pre-signature verification test.')
            else:
                print(' * Failed  pre-signature verification test.')
                print('   Expected pre-signature verification result:', result)
                print('     Actual pre-signature verification result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    return all_passed

def adapt_test_vectors() -> bool:
    all_passed = True
    with open(os.path.join(sys.path[0], 'vectors/adapt_vectors.csv'), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, pubkey_hex, msg_hex, secadaptor_hex, presig_hex, bip340sig_hex, result_str, comment) = row
            # ignores the last row which doesn't contain any test vectors
            if index == '':
                continue
            secadaptor = bytes.fromhex(secadaptor_hex)
            presig = bytes.fromhex(presig_hex)
            bip340sig = bytes.fromhex(bip340sig_hex)
            msg = bytes.fromhex(msg_hex)
            pubkey = XonlyPk(bytes.fromhex(pubkey_hex))
            result = result_str == 'TRUE'
            print('\nTest vector', ('#' + index).rjust(3, ' ') + ':')

            bip340sig_actual = schnorr_adapt(presig, secadaptor)
            if bip340sig == bip340sig_actual:
                print(' * Adapted the pre-signature successfully!')
            else:
                print(' * Failed to adapt the pre-signature.')
                print('   Expected BIP340 signature:', bip340sig.hex().upper())
                print('     Actual BIP340 signature:', bip340sig_actual.hex().upper())
                all_passed = False

            result_actual = schnorr_verify(msg, pubkey, bip340sig)
            if result == result_actual:
                print(' * Passed adapt test.')
            else:
                print(' * Failed adapt test.')
                print('   Expected adapt result:', result)
                print('     Actual adapt result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    return all_passed

def secadaptor_test_vectors() -> bool:
    all_passed = True
    with open(os.path.join(sys.path[0], 'vectors/secadaptor_vectors.csv'), newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, presig_hex, bip340sig_hex, secadaptor_hex, result_str, comment) = row
            # ignores the last row which doesn't contain any test vectors
            if index == '':
                continue
            presig = bytes.fromhex(presig_hex)
            bip340sig = bytes.fromhex(bip340sig_hex)
            secadaptor = bytes.fromhex(secadaptor_hex)
            result = result_str == 'TRUE'
            print('\nTest vector', ('#' + index).rjust(3, ' ') + ':')
            secadaptor_actual = schnorr_extract_secadaptor(presig, bip340sig)
            result_actual = secadaptor == secadaptor_actual
            if result == result_actual:
                print(' * Passed extract secadaptor test.')
            else:
                print(' * Failed extract secadaptor test.')
                print('   Result given in the CSV file:', result)
                print('   Actual result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    return all_passed

def run_test_vectors() -> None:
    test1 = presig_test_vectors()
    test2 = adapt_test_vectors()
    test3 = secadaptor_test_vectors()

    if test1 and test2 and test3 :
        print("All test vectors passed!!!")

def run_correctness_test_random(iters: int):
    for i in range(iters):
        print(".", end="", flush=True)
        sk = secrets.token_bytes(32)
        pk = pubkey_gen_xonly(sk)
        secadaptor = secrets.token_bytes(32)
        adaptor = pubkey_gen_plain(secadaptor)

        aux_rand = secrets.token_bytes(32)
        msg = secrets.token_bytes(32)

        presig = schnorr_presig_sign(msg, sk, aux_rand, adaptor)
        assert schnorr_presig_verify(msg, adaptor, pk, presig)

        sig = schnorr_adapt(presig, secadaptor)
        assert schnorr_verify(msg, pk, sig)

        extracted_secadaptor = schnorr_extract_secadaptor(presig, sig)
        assert (extracted_secadaptor == secadaptor)
    print("\nCorrectness test passed!!!")

if __name__ == "__main__":
    run_test_vectors()
    run_correctness_test_random(6)
