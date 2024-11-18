#!/usr/bin/python3
# TODO: Adjust to support PQ signing chains
import msgpack
import base64
import pysodium
from kafkacrypto.keys import get_pks
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
  pks = get_pks(pk[2])
  if isinstance(pks,(list,tuple)):
    pk[2] = pks[0]
    for pk0 in pks:
      print("Key:",str(pk0))
  else:
    pk[2] = pks
    print("Key:",str(pks))
  print("")

