#
# Author: Ilias Giechaskiel
# 
# This is a cleaned up version of the code I wrote for solving the 
# Introspective CRC problem in Google CTF 2017 Quals
# 
# The first part, when PRINT_EQS = True, prints the system of
# linear equations to be solved by Mathematica.
# The second part, when PRINT_SOLS = True, uses the solutions to
# the linear system and contacts the server to retrieve the flag.
# 
# For more details, please visit
# https://ilias.giechaskiel.com/posts/google_ctf_crc/index.html
#

from pwn import *

# Output parameters
PRINT_EQS = True
PRINT_SOLS = False

# CRC Parameters
W = 82
d = 0x308c0111011401440411
D = BitPolynom(int(d)) | (1 << W)

# This is the polynomial corresponding to W "0" characters (not number "\x00")
# Adapted from the initialization in generic_crc 
# https://github.com/Gallopsled/pwntools/blob/stable/pwnlib/util/crc/__init__.py
R0 = (BitPolynom(packing.unpack(fiddling.bitswap("0"*W), 'all', endian='big', sign=False)) << W) % D

def get_coeffs(poly):
    return '{0:b}'.format(fiddling.bitswap_int(poly.n, W)).rjust(W, "0")

r0_coeffs = get_coeffs(R0) # Coefficients of all 0s remainder
rems = [] # rems[i] holds the remainder R_i 
unknowns = [] # unknowns[i] holds the i-th variable a_i
for i in xrange(W):
    unknowns.append("a" + str(i))
    poly = BitPolynom(1 << (W + 7 + 8*i)) % D
    rems.append(get_coeffs(poly))


# This prints the system of equations in the format expected by Mathematica
if PRINT_EQS:
    print "ans = Solve[{",

    # Prints the W equations
    for exp in xrange(W):
        if exp > 0:
            print ","
        print r0_coeffs[exp],

        for i in xrange(W):
            print "+", rems[i][exp],"*", unknowns[i],

        # Because of how refin and refout work in generic_crc
        print "==", unknowns[W - 1 - exp],
        
    print "}, {",

    # Prints the unknowns to solve for
    for i in xrange(W):
        if i > 0:
            print ",",
        print unknowns[i],

    print "}, Modulus -> 2]"


if PRINT_SOLS:
    # These solutions come from Mathematica

    # 1010010010111000110111101011101001101011011000010000100001011100101001001100000000
    solution = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, \
    0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, \
    0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, \
    1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1]

    # 1111110111111011001110001110101000001010101001100111010000100000010011101011100010
    alt_solution = [0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, \
    1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, \
    0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, \
    1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1]

    # Represent as string and reverse
    solution = ''.join([str(s) for s in solution][::-1])
    print solution, "(Solution)"
    print '{0:b}'.format(crc.crc_82_darc(solution)).rjust(W, "0"), "(CRC)"

    r = remote('selfhash.ctfcompetition.com', 1337)
    r.sendline(solution)
    print r.recvall() # CTF{i-hope-you-like-linear-algebra}