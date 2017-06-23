# coding:utf-8

from Crypto.Util.number import getPrime
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
from random import randint

# Reference for modulo inverse:
# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
# ======== Extended Euclidean algorithm ========
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# ======== mod inverse ========
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class Elgamal:
    class Pubkey:
        def __init__(self):
            pass
        def setKey(self, y, g, p):
            self.y = y
            self.g = g
            self.p = p
    def __init__(self):
        self.pubkey = self.Pubkey()

    def genKey(self, bits):
        p = getPrime(bits)
        g = randint(1,p-1)
        x = randint(1,p-1)
        y = pow(g,x,p)
        self.seckey = x
        self.pubkey.setKey(y, g, p)

    def enc(self, plain):
        y = self.pubkey.y
        g = self.pubkey.g
        p = self.pubkey.p

        m = b2l(plain)
        r = randint(1,p-1)
        c1 = pow(g, r, p)
        c2 = ( pow(y, r, p) * m ) % p
        cipher = (c1, c2)
        return cipher

    def dec(self, cipher): # こっちは数値でやる
        c1, c2 = cipher
        p = self.pubkey.p
        x = self.seckey
        
        m = (pow(modinv(c1,p),x,p) * c2) % p
        plain = l2b(m)
        
        return plain


def main():
    elg = Elgamal()
    elg.genKey(512) # Key length
    print "==== Public Keys ===="
    print " y:", elg.pubkey.y
    print " g:", elg.pubkey.g
    print " p:", elg.pubkey.p
    print
    print "==== Secret Key ===="
    print " x:", elg.seckey
    print


    plain = "This is test message."
    print "==== Plain Text ===="
    print "", plain
    print

    cipher = elg.enc(plain)
    print "==== Encryption Result (c1, c2) ===="
    print "",cipher
    print

    dec = elg.dec(cipher)
    print "==== Decryption Result ===="
    print "",dec


if __name__ == "__main__":
    main()
