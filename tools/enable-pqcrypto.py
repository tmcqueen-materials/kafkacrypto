#!/usr/bin/env python3
import msgpack

file = input('Cryptokey file to enable pqcrypto in (ends in .crypto)? ')
with open(file, 'rb') as f:
  data = f.read()
contents = msgpack.unpackb(data,raw=True)
print(contents)
if len(contents) < 5:
  print("Cryptokey file is not in a versioned format.")
  exit(1)
contents[4] = [2,1] # change to [2] to enable *only* the Curve25519+sntrup761 hybrid, and to [1] to enable only non-pq key exchange
with open(file, 'wb') as f:
  f.write(msgpack.packb(contents, use_bin_type=True))
with open(file, 'rb') as f:
  data = f.read()
contents = msgpack.unpackb(data,raw=True)
print(contents)

