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
contents[4] = [5,2,1] # 5 = Curve25519+ML-KEM-1024, 2 = Curve25519+sntrup761 hybrid, 1 = non-pq curve25519
with open(file, 'wb') as f:
  f.write(msgpack.packb(contents, use_bin_type=True))
with open(file, 'rb') as f:
  data = f.read()
contents = msgpack.unpackb(data,raw=True)
print(contents)

