from time import time
import pysodium
import msgpack

def process_chain(topic, rot, chain, usage):
  #
  # chain should be a single msgpack array, with the next item in the array
  # signed by the entity with public key given in the current item. The first
  # item must be signed by the root of trust. Each (signed) item is itself a
  # msgpack array containing:
  # (0) a max_age timestamp (64-bit unsigned unix maximum time signature is valid)
  # (1) a poison array. Sets allowed signature key uses
  # (2) public key
  # Possibly more items in (3)+, especially common for the final item,
  # but not needed to check the chain
  #
  if (len(rot) > 0):
    val = [rot] + msgpack.unpackb(chain)
  else:
    val = msgpack.unpackb(chain)
  pk = None
  for npk in val:
    if not (pk is None):
      pk = msgpack.unpackb(pysodium.crypto_sign_open(npk, pk[2]))
    else:
      pk = msgpack.unpackb(npk) # root is unsigned
    if (len(pk) < 3 or (pk[0]<time() and pk[0]>0)):
      raise ValueError("Invalid Signature on Chain")
    poison = msgpack.unpackb(pk[1])
    for ku in poison:
      if (ku[0] == b'topics'):
        if (not (topic in ku[1]) and len(topic)>0):
          raise ValueError("Chain signature used for disallowed topic")
      elif (ku[0] == b'usages'):
        if (not (usage in ku[1]) and len(usage)>0):
          raise ValueError("Chain signature used for disallowed usage")
      else:
        raise ValueError("Unknown chain signature poison")
  return pk
