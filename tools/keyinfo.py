#!/usr/bin/python3
import msgpack
import base64
import pysodium
rot=base64.b64decode('kwDEAZDEIHn1MDouHBP7X1w945IARpSuHVVsCdwAA7B4E2+AWXKh')
chain = base64.b64decode('chain-to-analyze')
try:
  chain=msgpack.unpackb(chain,raw=False)
  legacy=False
except:
  print("Warning: Legacy chain.")
  legacy=True
  chain=msgpack.unpackb(chain,raw=True)
chain = [rot] + chain
pk = None
for npk in chain:
  if pk!=None:
    pk = msgpack.unpackb(pysodium.crypto_sign_open(npk, pk[2]), raw=legacy)
  else:
    pk=msgpack.unpackb(npk, raw=legacy)
  print("Raw Key:",base64.b64encode(msgpack.packb(pk,use_bin_type=(not legacy))))
  print("Timestamp:",pk[0])
  print("Posion:",msgpack.unpackb(pk[1], raw=legacy))
  print("Key:",pk[2].hex())
  print("")

