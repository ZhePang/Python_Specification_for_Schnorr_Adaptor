import sys
from reference import *
import csv

infinity = None

#
# `schnorr_presig_sign` test vectors
#
def vector0():
    seckey = bytes_from_int(3)
    msg = bytes_from_int(0)
    aux_rand = bytes_from_int(0)

    # We should have at least one test vector where the adaptor has an even
    # Y coordinate and one where it has an odd Y coordinate. In this one Y is even
    secadaptor_ = 2
    adaptor_ = point_mul(G, secadaptor_)
    assert(has_even_y(adaptor_))

    adaptor = cbytes(adaptor_)
    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
    pubkey = pubkey_gen(seckey, True)

    # We should have at least one test vector where the seckey needs to be
    # negated and one where it doesn't. In this one the seckey doesn't need to
    # be negated.
    x = int_from_bytes(seckey)
    P = point_mul(G, x)
    assert(y(P) % 2 == 0)

    return (seckey, pubkey, aux_rand, msg, adaptor, presig, "TRUE", "The seckey and secadaptor values are small")

def vector1():
    seckey = bytes_from_int(0x0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710)

    # Need to negate this seckey before signing
    x = int_from_bytes(seckey)
    P = point_mul(G, x)
    assert(y(P) % 2 != 0)

    msg = bytes_from_int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    aux_rand = bytes_from_int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)

    # The adaptor has an odd Y coordinate.
    secadaptor_ = 0x8B915D93B818468A035B06D6D4FF53EB6F22D9CF2B918B8DEEB59EEB3327EDAE
    adaptor = cbytes(point_mul(G, secadaptor_))
    assert(not has_even_y(adaptor))

    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)

    return (seckey, pubkey_gen(seckey, True), aux_rand, msg, adaptor, presig, "TRUE", "test fails if msg is reduced modulo p or n")

# Signs with a given nonce and secadaptor. This can be INSECURE and is only INTENDED FOR
# GENERATING TEST VECTORS. The regular signing algorithm should take adaptor instead of
# secadatpor.
def insecure_schnorr_presig_sign(msg, seckey0, k0, t):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    assert (k0 <= n - 1)
    assert (t <= n - 1)
    seckey0 = int_from_bytes(seckey0)
    if not (1 <= seckey0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, seckey0)
    seckey = seckey0 if has_even_y(P) else n - seckey0
    R = point_mul(G, k0)
    T = point_mul(G, t)
    R0 = point_add(R, T)
    k = k0 if has_even_y_ext(R0) else n - k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", xbytes_ext(R0) + xbytes_ext(P) + msg)) % n
    # we use `cbytes_ext` to allow encoding the infinity point
    return cbytes_ext(R0) + bytes_from_int((k + e * seckey) % n)

def xbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(32, byteorder='big')
    assert P is not None
    return xbytes(P)

def cbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(33, byteorder='big')
    assert P is not None
    return cbytes(P)

def has_even_y_ext(P: Optional[Point]) -> bool:
    if is_infinite(P):
        return True
    assert P is not None
    return y(P) % 2 == 0

# create a signature with small x(R') using k + t = 1/2
def vector2():
    seckey = bytes_from_int(0x763758E5CBEEDEE4F7D3FC86F531C36578933228998226672F13C4F0EBE855EB)
    msg = bytes_from_int(0x4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703)
    # compute 1/4 mod n
    k0 = pow(4, n - 2, n)
    t = pow(4, n - 2, n)
    one_half = n - 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    assert (k0 + t) % n == one_half

    presig  = insecure_schnorr_presig_sign(msg, seckey, k0, t)
    secadaptor = bytes_from_int(t)

    return (None, pubkey_gen(seckey, True), None, msg, pubkey_gen(secadaptor, False), presig, "TRUE", None)

default_seckey = bytes_from_int(0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF)
default_msg = bytes_from_int(0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89)
default_aux_rand = bytes_from_int(0xC87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906)
default_secadaptor = bytes_from_int(0x848BC87F32C6F71D3A93A59424584562046F31693716FF73A897CCC1659C5F5D)

#
# `schnorr_extract_adaptor` test vectors
#

# Public key not on the curve
# Purpose: `lift_x(pubkey)` will fail
def vector3():
    # This creates a dummy signature that doesn't have anything to do with the
    # public key.
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)

    pubkey = bytes_from_int(0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34)
    assert(lift_x(int_from_bytes(pubkey)) is None)

    return (None, pubkey, None, msg, adaptor, presig, "FALSE", "public key not on the curve")

# Check that calling `try_fn` raises a `exception`. If `exception` is raised,
# examine it with `except_fn`.
def assert_raises(exception, try_fn, except_fn):
    raised = False
    try:
        try_fn()
    except exception as e:
        raised = True
        assert(except_fn(e))
    except BaseException:
        raise AssertionError("Wrong exception raised in a test.")
    if not raised:
        raise AssertionError("Exception was _not_ raised in a test where it was required.")

exception = ValueError
except_fn = lambda e: str(e) == 'x is not a valid compressed point.'

# x-coordinate of public key equal to field size
# Purpose: `lift_x(pubkey)` will fail
def vector4():
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)

    pubkey = bytes_from_int(p)
    assert(lift_x(int_from_bytes(pubkey)) is None)

    return (None, pubkey, None, msg, adaptor, presig, "FALSE", "x-coordinate of public key equal to field size")


# presig[1:33] (R'.x) is not on the curve
# Purpose: The lift_x(R') call inside cpoint(R') will fail
def vector5():
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)
    rx = bytes_from_int(0xEEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34)
    presig = presig[0:1] + rx + presig[33:]
    assert(lift_x(int_from_bytes(presig[1:33])) is None)
    assert_raises(exception, lambda: cpoint(presig[0:33]), except_fn)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "presig[1:33] is not on the curve")

# presig[1:33] (R'.x) is equal to field size
# Purpose: The lift_x(R') call inside cpoint(R') will fail
def vector6():
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)

    presig = presig[0:1] + bytes_from_int(p) + presig[33:]
    assert(lift_x(int_from_bytes(presig[1:33])) is None)
    assert_raises(exception, lambda: cpoint(presig[0:33]), except_fn)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "presig[1:33] equal to field size")

# The parity of R' is invalid
# Purpose: The cpoint(R') will fail
def vector7():
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)
    presig = b'\x04' + presig[1:]
    assert_raises(exception, lambda: cpoint(presig[0:33]), except_fn)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "The first byte of presig (parity byte) is invalid")

# parity of R' is flipped
# Purpose: `adaptor_expected == adaptor` check in `presig_verify` will fail
def vector8():
    seckey = default_seckey
    pubkey = pubkey_gen(seckey, True)
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)
    # flip the last bit of the parity byte (makes 2 -> 3 and 3 -> 2)
    neg_parity = (presig[0] ^ 1).to_bytes(1, 'big')
    presig = neg_parity + presig[1:]

    # check if flipping R'.y also flips the y-coordinate of adaptor
    extracted_adaptor = schnorr_extract_adaptor(msg, pubkey, presig)
    assert extracted_adaptor is not None
    T1 = cpoint(adaptor)
    T2 = cpoint(extracted_adaptor)
    assert (adaptor != extracted_adaptor)
    assert (T1 == point_negate(T2))

    return (None, pubkey, None, msg, adaptor, presig, "FALSE", "The LSB of the first byte of presig (parity byte) is flipped")

# It's cryptographically impossible to create a test vector that fails if run
# in an implementation which merely misses the check that presig[32:64] is smaller
# than the curve order. This test vector just increases test coverage.
# Purpose: hits the `s0 >= n` check
def vector9():
    seckey = default_seckey
    msg = default_msg
    adaptor = pubkey_gen(default_secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)

    # Replace s with a number that's equal to the curve order
    presig = presig[0:33] + bytes_from_int(n)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "presig[33:65] is equal to the curve order")


def vector10():
    seckey = default_seckey
    adaptor = pubkey_gen(default_secadaptor, False)
    msg = int_from_bytes(default_msg)
    neg_msg = bytes_from_int(n - msg)
    presig = schnorr_presig_sign(neg_msg, seckey, default_aux_rand, adaptor)
    return (None, pubkey_gen(seckey, True), None, bytes_from_int(msg), adaptor, presig, "FALSE", "negated message")

def vector11():
    seckey = default_seckey
    adaptor = pubkey_gen(default_secadaptor, False)
    msg = default_msg
    presig = schnorr_presig_sign(msg, seckey, default_aux_rand, adaptor)
    presig = presig[0:33] + bytes_from_int(n - int_from_bytes(presig[33:65]))

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "negated presig[33:65] value")

# create a pre-signature  with k = 0
# Purpose: hits the `R0 is None` check
def vector12():
    seckey = default_seckey
    msg = default_msg
    k = 0
    t = int_from_bytes(default_secadaptor)
    presig = insecure_schnorr_presig_sign(msg, seckey, k, t)
    adaptor = pubkey_gen(default_secadaptor, False)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "s'G - eP is infinite")

# create pre-signature with t = 0
# Purpose: hits the `T is None` check
def vector13():
    seckey = default_seckey
    msg = default_msg
    t = 0
    # some random non-zero value for `k`
    k = 0x763758E5CBEEDEE4F7D3FC86F531C36578933228998226672F13C4F0EBE855EB
    presig = insecure_schnorr_presig_sign(msg, seckey, k, t)
    adaptor = cbytes_ext(infinity)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "R' - (s'G - eP) is infinite")

# create pre-signature with k = 0 and t = 0
# Purpose: improve test coverage
def vector14():
    seckey = default_seckey
    msg = default_msg
    k, t = 0, 0
    presig = insecure_schnorr_presig_sign(msg, seckey, k, t)
    adaptor = cbytes_ext(infinity)
    assert_raises(exception, lambda: cpoint(presig[0:33]), except_fn)

    return (None, pubkey_gen(seckey, True), None, msg, adaptor, presig, "FALSE", "R' - (s'G - eP) is infinite")

#
# `schnorr_adapt` test vectors
#

def vector15():
    seckey = default_seckey
    aux_rand = default_aux_rand
    secadaptor = default_secadaptor
    adaptor = pubkey_gen(secadaptor, False)
    msg = int_from_bytes(default_msg)
    neg_msg = bytes_from_int(n - msg)
    presig_neg = schnorr_presig_sign(neg_msg, seckey, aux_rand, adaptor)
    bip340sig = schnorr_adapt(presig_neg, secadaptor)
    return (pubkey_gen(seckey, True), bytes_from_int(msg), secadaptor, presig_neg, bip340sig, "FALSE", "adapt a pre-signature generated on negated message")

#
# `schnorr_extract_secadaptor` and `schnorr_adapt` test vectors
#

# Note:
#    didn't add extract_secadaptor vectors for `s0 >= n` & `s >= n` because they raise value error
#    didn't add adapt vectors for `s0 >= n` & `t >= n` because they raise value error

# pre-signature where presig[0] is 0x03
# Purpose: hits the `s = (s0 - t) % n` branch in `schnorr_adapt`
#          hits the `t = (s0 - s) % n` branch in `schnorr_extract_secadaptor`
def vector16(vectype):
    msg = bytes_from_int(0x389575B92B586BE2730A998241E5CF651D6C191FA64EEA3D00256AFF7D18484F)
    aux_rand = bytes_from_int(0x20E71D6198A2D8096D44180BC0E0D02D8B215AE6F1311AD1F03B6040E4C41889)
    seckey = bytes_from_int(0x84BCB0C86AF195C590A04C5E97D2D17EDB2A35A82A162D2C0CB2E0923629FC8B)
    pubkey = pubkey_gen(seckey, True)
    secadaptor = bytes_from_int(0xE5E68D0E637DA4822732E20F3EEBE1826892E81C2CFEC6BEC600CDA3F66A53F1)
    adaptor = pubkey_gen(secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
    assert presig[:1] == b'\x03'
    bip340sig = schnorr_adapt(presig, secadaptor)
    if vectype == 'adapt':
        return (pubkey, msg, secadaptor, presig, bip340sig, "TRUE", "adapt a pre-signature whose first byte is 0x03")
    elif vectype == 'secadaptor':
        return (presig, bip340sig, secadaptor, "TRUE", "extract secadaptor from a pre-signature whose first byte is 0x03")

# adapt the pre-signature where presig[0] is 0x02
# Purpose: hits the `s = (s0 + t) % n` branch in `schnorr_adapt`
#          hits the `t = (s - s0) % n` branch in `schnorr_extract_secadaptor`
def vector17(vectype):
    msg = bytes_from_int(0x2F4E505E2C70E81B94431800F810ECB04FD0AAEEB0C703F8DCE44EEDFA0AB8C2)
    aux_rand = bytes_from_int(0xFBCB7B7E86899D0D4BE438F415746F39CA19CD0C43721632B2CE19D37C211382)
    seckey = bytes_from_int(0xDBF97DE24E9197B78F6166B15B870A85DB1337099393F85E07A521919740B1EF)
    pubkey = pubkey_gen(seckey, True)
    secadaptor = bytes_from_int(0x539212A1B9FC42F44AD1A57720C744408403FFFF805848664027FC9C74B3876A)
    adaptor = pubkey_gen(secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
    assert presig[:1] == b'\x02'
    bip340sig = schnorr_adapt(presig, secadaptor)
    if vectype == 'adapt':
        return (pubkey, msg, secadaptor, presig, bip340sig, "TRUE", "adapt a pre-signature whose first byte is 0x02")
    elif vectype == 'secadaptor':
        return (presig, bip340sig, secadaptor, "TRUE", "extract secadaptor from a pre-signature whose first byte is 0x02")

#todo: we should adapt the neg_presig, not the presig
#todo: how does this affect the extract_secadaptor?
def vector18(vectype):
    msg = default_msg
    seckey = default_seckey
    aux_rand = default_aux_rand
    secadaptor = default_secadaptor
    adaptor = pubkey_gen(secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
    presig_neg = presig[0:33] + bytes_from_int(n - int_from_bytes(presig[33:65]))
    bip340sig = schnorr_adapt(presig_neg, secadaptor)
    if vectype == 'adapt':
        return (pubkey_gen(seckey, True), msg, secadaptor, presig_neg, bip340sig, "FALSE", "adapt a pre-signature with negated s' value")
    elif vectype == 'secadaptor':
        return (presig, bip340sig, secadaptor, "FALSE", "extract secadaptor from bip340 signature created by adapting a pre-signature with negated s' value")

def vector19(vectype):
    msg = default_msg
    seckey = default_seckey
    aux_rand = default_aux_rand
    secadaptor = default_secadaptor
    adaptor = pubkey_gen(secadaptor, False)
    presig = schnorr_presig_sign(msg, seckey, aux_rand, adaptor)
     # flip the last bit of the parity byte (makes 2 -> 3 and 3 -> 2)
    neg_parity = (presig[0] ^ 1).to_bytes(1, 'big')
    neg_presig = neg_parity + presig[1:]
    bip340sig = schnorr_adapt(neg_presig, secadaptor)
    if vectype == 'adapt':
        return (pubkey_gen(seckey, True), msg, secadaptor, neg_presig, bip340sig, "FALSE", "adapt a pre-signature with negated R' value")
    elif vectype == 'secadaptor':
        return (presig, bip340sig, secadaptor, "FALSE", "extract secadaptor from bip340 signature created by adapting a pre-signature with negated R' value")

#
# The following code is only used to create a CSV file containing the above test vectors.
#

# Converts the byte strings of a vector into hex strings
def vector_to_hex(vector):
    hex_fields = []
    for field in vector:
        # don't apply .hex().upper() on "result", "comment" columns
        if field is None or field in (vector[-2], vector[-1]):
            hex_fields.append(field)
        else:
            hex_fields.append(field.hex().upper())
    return tuple(hex_fields)

def print_csv(vectors, vectype):
    writer = csv.writer(sys.stdout)
    header_row = {
        "presig": ("index", "secret key", "public key", "aux_rand", "message", "adaptor", "pre-signature", "result", "comment"),
        "adapt": ("index", "pubkey", "message", "secadaptor", "pre-signature", "BIP340 signature", "result", "comment"),
        "secadaptor": ("index", "pre-signature", "BIP340 signature", "secadaptor", "result", "comment")
    }
    writer.writerow(header_row[vectype])

    side_note = {
        "presig": ("", "", "", "", "", "", "", "", "The result column represents the output of schnorr_presig_verify()"),
        "adapt": ("", "", "", "", "", "", "", "The result column represents the output of schnorr_verify() on the adapted pre-signature"),
        "secadaptor": ("", "", "", "", "", "The result column represents the output of secadaptor == schnorr_extract_secadaptor()")
    }
    writer.writerow(side_note[vectype])

    for (i, vector) in enumerate(vectors):
        writer.writerow((i,) + vector)

if __name__ == "__main__":
    presig_vectors = [
        vector0(), vector1(), vector2(), vector3(), vector4(),
        vector5(), vector6(), vector7(), vector8(), vector9(),
        vector10(), vector11(), vector12(), vector13(), vector14()
    ]
    adapt_vectors = [
        vector15(), vector16('adapt'), vector17('adapt'), vector18('adapt'), vector19('adapt')
    ]
    secadaptor_vectors = [
        vector16('secadaptor'), vector17('secadaptor'), vector18('secadaptor'), vector19('secadaptor')
    ]

    presig_vectors_hex = [vector_to_hex(vector) for vector in presig_vectors]
    adapt_vectors_hex = [vector_to_hex(vector) for vector in adapt_vectors]
    secadaptor_vectors_hex = [vector_to_hex(vector) for vector in secadaptor_vectors]

    # Create a subdirectory to put the vector CSV files
    os.makedirs("vectors", exist_ok=True)

    # File names for CSV outputs
    output_files = {
        "presig": "vectors/presig_vectors.csv",
        "adapt": "vectors/adapt_vectors.csv",
        "secadaptor": "vectors/secadaptor_vectors.csv"
    }

    # Write vectors to CSV files
    for vectype, filename in output_files.items():
        with open(filename, "w") as f:
            sys.stdout = f
            if vectype == "presig":
                print_csv(presig_vectors_hex, "presig")
            elif vectype == "adapt":
                print_csv(adapt_vectors_hex, "adapt")
            elif vectype == "secadaptor":
                print_csv(secadaptor_vectors_hex, "secadaptor")