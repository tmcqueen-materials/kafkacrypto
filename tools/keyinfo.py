#!/usr/bin/python3
import msgpack
import base64
import pysodium
rot=base64.b64decode('kwChkNoAIHn1MDouHBP7X1w945IARpSuHVVsCdwAA7B4E2+AWXKh')
chain = base64.b64decode('chain-to-analyze')
chain=msgpack.unpackb(chain,raw=True)
chain = [rot] + chain
pk = None
for npk in chain:
  if pk!=None:
    pk = msgpack.unpackb(pysodium.crypto_sign_open(npk, pk[2]), raw=True)
  else:
    pk=msgpack.unpackb(npk, raw=True)
  print("Raw (Old):",base64.b64encode(msgpack.packb(pk,use_bin_type=False)))
  print("Raw (New):",base64.b64encode(msgpack.packb(pk,use_bin_type=True)))
  print("Timestamp:",pk[0])
  print("Posion:",msgpack.unpackb(pk[1], raw=True))
  print("Key:",pk[2].hex())
  print("")

