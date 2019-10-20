#!/usr/bin/python3
import msgpack
import base64
import pysodium
rot=base64.b64decode('kwChkNoAIHn1MDouHBP7X1w945IARpSuHVVsCdwAA7B4E2+AWXKh')
chain = base64.b64decode('chain-to-analyze')
chain=msgpack.unpackb(chain)
chain = [rot] + chain
pk = None
for npk in chain:
  if pk!=None:
    pk = msgpack.unpackb(pysodium.crypto_sign_open(npk, pk[2]))
  else:
    pk=msgpack.unpackb(npk)
  print("Raw:",base64.b64encode(msgpack.packb(pk)))
  print("Timestamp:",pk[0])
  print("Posion:",msgpack.unpackb(pk[1]))
  print("Key:",pk[2].hex())
  print("")

