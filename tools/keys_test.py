#!/usr/bin/env python
# Requires python version >= 2.7.8

import hashlib, binascii, base64

def print_array(name, v):
    print name + " := []byte{",
    i = 0
    for b in v:
        if i % 8 == 0:
            print "\n   ",
        print "0x{:02X},".format(ord(b)),
        i += 1
    print "\n}"

print base64.b64encode(chr(0) * 32)
print base64.b64encode(chr(1) * 32)

print "===="

k = hashlib.pbkdf2_hmac('sha512', 'password', chr(0) * 32, 100000, 32)
print_array("cryptoKey", k)

print "===="

k = int(hashlib.pbkdf2_hmac('sha512', 'password', chr(1) * 32, 100000, 521 / 8 + 8).encode('hex'), 16)
n = int("68647976601306097149819007990813932172694353"
        "00143305409394463459185543183397655394245057"
        "74633321719753296399637136332111386476861244"
        "0380340372808892707005449")
k = k % (n - 1) + 1
s = "{:x}".format(k)
if len(s) & 1:
    s = '0' + s
s = s.decode('hex')
print_array("signingKeyBytes", s)
