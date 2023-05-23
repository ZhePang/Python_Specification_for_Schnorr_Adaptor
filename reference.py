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

def schnorr_pre_sign(msg: bytes, seckey: bytes, aux_rand: bytes, T: Point) -> bytes:
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    d0 = int_from_bytes(seckey) #private key
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, d0) #public key
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n #nonce r
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0) # elliptic curve point R=rG
    assert R is not None
    k = n - k0 if not has_even_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(point_add(R, T)) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(T) + bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    debug_print_vars()
    if not schnorr_pre_verify(msg, T, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_pre_verify(msg: bytes, T: Point, pubkey: bytes, pre_sig: bytes) -> bool:
    return True

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


# Helper Functions

import os

def generate_aux_rand() -> bytes:
    return os.urandom(32)

def message_encode_32bytes(msg: str) -> bytes:
    return hashlib.sha256(msg.encode()).digest()

def test_pre_sign() -> bool:
    msg = message_encode_32bytes("test")
    print("msg:  " + msg.hex())
    seckey = bytes_from_int(1)
    print("seckey:  " + seckey.hex())
    aux_rand = generate_aux_rand()
    print("aux_rand:  " + aux_rand.hex())
    T = point_mul(G, 2)
    assert T is not None
    print("T:  " + bytes_from_point(T).hex())
    sig = schnorr_pre_sign(msg, seckey, aux_rand, T)
    print("sig:  " + sig.hex())
    print("sig_T:  " + sig[:32].hex())
    print("sig_R:  " + sig[32:64].hex())
    print("sig_sig:  " + sig[64:].hex())
    return True

if __name__ == "__main__":
    test_pre_sign()