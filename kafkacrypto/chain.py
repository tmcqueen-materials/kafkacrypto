from time import time
import pysodium
import msgpack

def process_chain(topic, rot, chain, usage, denylist=None):
  #
  # chain should be a single msgpack array, with the next item in the array
  # signed by the entity with public key given in the current item. The first
  # item must be signed by the root of trust. Each (signed) item is itself a
  # msgpack array containing:
  # (0) a max_age timestamp (64-bit unsigned unix maximum time signature is valid)
  # (1) a poison array. Sets allowed signature key uses
  # (2) public key
  # Possibly more items in (3)+, especially common for the final item,
  # but not needed to check the chain.
  #
  # Returns a ValueError if chain does not match topic or usage criteria, or
  # uses a denylisted key. 
  #
  # Otherwise, returns an array containing:
  # (0) The minimum max_age timestamp
  # (1) The intersection of allowed topics and usage, in the
  #     poison array
  # (2) The public key
  # And any items in (3)+ from the final item.
  #
  min_max_age = 0
  poison_topics = None
  poison_usages = None
  if (len(rot) > 0):
    val = [rot] + msgpack.unpackb(chain)
  else:
    val = msgpack.unpackb(chain)
  pk = None
  for npk in val:
    if not (pk is None):
      if (not (denylist is None)) and pk[2] in denylist:
        raise ValueError("Chain uses denylisted signing key.")
      pk = msgpack.unpackb(pysodium.crypto_sign_open(npk, pk[2]))
    else:
      pk = msgpack.unpackb(npk) # root is unsigned
    if (len(pk) < 3):
      raise ValueError("Invalid Chain")
    if (pk[0]<time() and pk[0]>0):
      raise ValueError("Expired Chain")
    if (pk[0]>0 and (min_max_age == 0 or pk[0]<min_max_age)):
      min_max_age = pk[0]
    poison = msgpack.unpackb(pk[1])
    for ku in poison:
      if (ku[0] == b'topics'):
        if (len(topic) > 0 and not (topic in ku[1])):
          raise ValueError("Chain signature used for disallowed topic")
        if poison_topics is None:
          poison_topics = ku[1]
        else:
          poison_topics = list(set(poison_topics).intersection(ku[1]))
      elif (ku[0] == b'usages'):
        if (len(usage) > 0 and not (usage in ku[1])):
          raise ValueError("Chain signature used for disallowed usage")
        if poison_usages is None:
       	  poison_usages = ku[1]
       	else:
       	  poison_usages = list(set(poison_usages).intersection(ku[1]))
      else:
        raise ValueError("Unknown chain signature poison")
  pk[0] = min_max_age
  poison = []
  if not (poison_topics is None):
    if len(poison_topics) < 1:
      raise ValueError("Zero topics in allowed intersection set.")
    poison.append([b'topics',poison_topics])
  if not (poison_usages is None):
    if len(poison_usages) < 1:
      raise ValueError("Zero usages in allowed intersection set.")
    poison.append([b'usages',poison_usages])
  pk[1] = msgpack.packb(poison)
  return pk
