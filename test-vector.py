import sys
from reference import *
import csv

def is_square(x):
    return int(pow(x, (p - 1) // 2, p)) == 1

def has_square_y(P):
    """Determine if P has a square Y coordinate. Used in an earlier draft of BIP340."""
    assert not is_infinite(P)
    return is_square(P[1])

def point_to_bytes(P):
    return (bytes_from_int(P[0]), bytes_from_int(P[1]))

def vector0():
    seckey = bytes_from_int(3)
    msg = bytes_from_int(0)
    aux_rand = bytes_from_int(0)

    # We should have at least one test vector where the tag point T has an even
    # Y coordinate and one where it has an odd Y coordinate. In this one Y is even
    t = 2
    T = point_mul(G, t)
    assert(has_even_y(T))
    T = compress_point(T)
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(msg, seckey, aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    pubkey = pubkey_gen(seckey)

    # We should have at least one test vector where the seckey needs to be
    # negated and one where it doesn't. In this one the seckey doesn't need to
    # be negated.
    x = int_from_bytes(seckey)
    P = point_mul(G, x)
    assert(y(P) % 2 == 0)

    return (seckey, pubkey, aux_rand, msg, T, t, sig, sig64, None, "TRUE", "seckey and secadaptor are small")

def vector1():
    seckey = bytes_from_int(0x0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710)

    # Need to negate this seckey before signing
    x = int_from_bytes(seckey)
    P = point_mul(G, x)
    assert(y(P) % 2 != 0)

    msg = bytes_from_int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    aux_rand = bytes_from_int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    # The point T has an odd Y coordinate.
    t = 0X8B915D93B818468A035B06D6D4FF53EB6F22D9CF2B918B8DEEB59EEB3327EDAE
    T = compress_point(point_mul(G, t))
    assert(not has_even_y(T))
    t = bytes_from_int(t)


    sig = schnorr_presig_sign(msg, seckey, aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    return (seckey, pubkey_gen(seckey), aux_rand, msg, T, t, sig, sig64, None, "TRUE", "test fails if msg is reduced modulo p or n")

def vector2():
    seckey = bytes_from_int(0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9)
    msg = bytes_from_int(0x7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C)
    aux_rand = bytes_from_int(0xC87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D904)

    # The point T has an odd Y coordinate.
    t = 7
    T = point_negate(point_mul(G, t))
    assert(not has_even_y(T))
    T = compress_point(T)
    t = bytes_from_int(t)

    sig = schnorr_presig_sign(msg, seckey, aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    return (seckey, pubkey_gen(seckey), aux_rand, msg, T, t, sig, sig64, None, "TRUE", None)

default_seckey = bytes_from_int(0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF)
default_msg = bytes_from_int(0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89)
default_aux_rand = bytes_from_int(0xC87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906)
default_T = compress_point(point_mul(G, 5))

def vector3():
    # This creates a dummy signature that doesn't have anything to do with the
    # public key.
    seckey = default_seckey
    msg = default_msg
    sig = schnorr_presig_sign(msg, seckey, default_aux_rand, default_T)

    pubkey = bytes_from_int(0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34)
    assert(lift_x(int_from_bytes(pubkey)) is None)

    return (None, pubkey, None, msg, default_T, None, sig, None, "Verification", "FALSE", "Verification test: public key not on the curve")

def vector4():
    seckey = default_seckey
    msg = int_from_bytes(default_msg)
    neg_msg = bytes_from_int(n - msg)
    sig = schnorr_presig_sign(neg_msg, seckey, default_aux_rand, default_T)
    return (None, pubkey_gen(seckey), None, bytes_from_int(msg), default_T, None, sig, None, "Verification", "FALSE", "Verification test: negated message")

def vector5():
    seckey = default_seckey
    msg = default_msg
    t = 0X4EA9A26677381E8C0CCB187EEDE3568A4835D0A01816F78A5A787E5425395CEB
    T = compress_point(point_mul(G, t))
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(msg, seckey, default_aux_rand, T)
    sig = sig[0:33] + bytes_from_int(n - int_from_bytes(sig[33:65]))

    return (None, pubkey_gen(seckey), None, msg, T, None, sig, None, "Verification", "FALSE", "Verification test: negated s' value")

def vector6():
    seckey = default_seckey
    msg = default_msg
    sig = schnorr_presig_sign(msg, seckey, default_aux_rand, default_T)
    negated_parity = b"\x02" if sig[0] == 3 else b"\x03"
    sig = negated_parity + sig[1:]
    return (None, pubkey_gen(seckey), None, msg, default_T, None, sig, None, "Verification", "FALSE", "Verification test: negated R' value")

def vector7():
    seckey = default_seckey
    msg = default_msg
    sig = schnorr_presig_sign(msg, seckey, default_aux_rand, default_T)
    # We need to make R'.x invalid (32-byte) instead of an invalid 33-byte,
    # because the extract_adaptor API interprets R' as an x-only pubkey
    # rather than a regular compressed EC pubkey
    R0 = bytes_from_int(0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34)
    assert(lift_x(int_from_bytes(R0)) is None)
    sig = sig[0:1] + R0 + sig[33:65]
    return (None, pubkey_gen(seckey), None, msg, default_T, None, sig, None, "Verification", "FALSE", "Verification test: R' not on the curve")

def vector8():
    t = 75822971893802771970555672493312142286329633334319705105105405901505850897681
    T = compress_point(point_mul(G, t))
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(default_msg, default_seckey, default_aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    return (None, None, None, None, T, t, sig, sig64, "Adaptor extraction and Adapting", "TRUE", "Adaptor extraction and Adapting test: adaptor t is a large scalar")

def vector9():
    t = 102737890522302903489175669941446530087577081774431208355392319064688794746007
    T = compress_point(point_mul(G, t))
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(default_msg, default_seckey, default_aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    s = int_from_bytes(sig[33:65])
    sig = sig[0:33] + bytes_from_int(n - s)
    return (None, None, None, None, T, t, sig, sig64, "Adaptor extraction and Adapting", "FALSE", "Adaptor extraction and Adapting test: negated s' value")

def vector10():
    t = 102737890522302903489175669941446530087577081774431208355392319064688794746007
    T = compress_point(point_mul(G, t))
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(default_msg, default_seckey, default_aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    negated_parity = b"\x02" if sig[0] == 3 else b"\x03"
    sig = negated_parity + sig[1:]
    return (None, None, None, None, T, t, sig, sig64, "Adaptor extraction and Adapting", "FALSE", "Adaptor extraction and Adapting test: parity of R' is wrong")

def vector11():
    t = 102737890522302903489175669941446530087577081774431208355392319064688794746007
    T = compress_point(point_mul(G, t))
    t = bytes_from_int(t)
    sig = schnorr_presig_sign(default_msg, default_seckey, default_aux_rand, T)
    sig64 = schnorr_adapt(sig, t)
    R = bytes_from_int(0x9F08BE865F693BDBC1AE976DFFB8BC884C372052B0926E49E0298A9F2D7B4860)
    sig64 = R + sig64[32:64]
    return (None, None, None, None, T, t, sig, sig64, "Adapting", "FALSE", "Adapting test: R value does not match")


vectors = [
        vector0(),
        vector1(),
        vector2(),
        vector3(),
        vector4(),
        vector5(),
        vector6(),
        vector7(),
        vector8(),
        vector9(),
        vector10(),
        vector11(),
    ]

# Converts the byte strings of a test vector into hex strings
def bytes_to_hex(seckey, pubkey, aux_rand, msg, T, t, sig, sig64, test_type, result, comment):
    return (seckey.hex().upper() if seckey is not None else None, 
            pubkey.hex().upper() if pubkey is not None else None,
            aux_rand.hex().upper() if aux_rand is not None else None, 
            msg.hex().upper() if msg is not None else None,
            T.hex().upper() if T is not None else None, 
            t.hex().upper() if t is not None else None,
            sig.hex().upper(), 
            sig64.hex().upper() if sig64 is not None else None,
            test_type,
            result,
            comment)

vectors = list(map(lambda vector: bytes_to_hex(vector[0], vector[1], vector[2], vector[3], vector[4], vector[5], vector[6], vector[7], vector[8], vector[9], vector[10]), vectors))

def print_csv(vectors):
    writer = csv.writer(sys.stdout)
    writer.writerow(("index", "secret key", "public key", "aux_rand", "message", "adaptor", "secadaptor", "pre-signature", "bip340 signature", "target api", "result", "comment"))
    for (i,v) in enumerate(vectors):
        writer.writerow((i,)+v)

if __name__ == "__main__":
    output_file = "test_vectors.csv"
    with open(output_file, "w") as f:
        sys.stdout = f
        print_csv(vectors)