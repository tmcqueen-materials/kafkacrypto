from time import time
import pysodium
import msgpack
import logging
import re
from kafkacrypto.utils import str_shim_eq, str_shim_ne

class ProcessChainError(ValueError):
  def __init__(self, message, printable):
    super().__init__(message)
    self.printable = printable
  def __str__(self):
    rv = super().__str__()
    if not (self.printable) is None:
      rv += " " + str(self.printable)
    return rv

def key_in_list(wanted, choices):
  # choices is an array of zero or more msgpacked arrays, each of
  # which has the format of a chain entry (see below). This helper
  # function iterates each choice, seeing if the key wanted
  # is present, and returns the match (if any)
  # Right now this has O(n) running time in the length of choices,
  # a future improvement is to make the average running time
  # much faster by building a set of the pk's before calling
  # this function (scaling then is O(logn))
  if wanted is None or choices is None:
    return None
  for c in choices:
    pk = msgpack.unpackb(c,raw=True)
    if wanted == pk[2]:
      return c
  return None

def multimatch(wanted, choices):
  # choices is an array of zero or more items, and we return
  # True if wanted is matched by one or more items in choices, and
  # False otherwise. Choices is treated as literal
  # strings except if it starts with "^", in which case it is
  # treated as a regular expression. This matches behaviors
  # of many other libraries, including librdkafka.
  # Wanted is also treated as a literal except if it
  # starts with "^", in which case it is treated as a regular
  # expression. wanted is in choices if:
  #  1. Wanted is a literal, and exactly matches a literal in
  #     choices. [OR]
  #  2. Wanted is a literal, and is matched by a regex in
  #     choices. [OR]
  #  3. Wanted is a regex, and exactly matches a regex in
  #     choices. [OR]
  #  4. Wanted is a regex, and choices as the "match everything"
  #     regex ("^.*$") in it.
  # In particular, this means that regexs in choices are only
  # considered to match a regex wanted if the two (treated as
  # literals) exactly match. This is to ensure that wanted
  # is a strict subset of what choices allows. In principle
  # the regexes could be converted to NFA/DFAs and then checked
  # to ensure a wanted regex is a strict subset of a choices
  # regex, but this is presently unimplemented. It does mean
  # that multimatch is, in some cases, more restrictive than
  # strictly necessary, but this is better than being less
  # restrictive (which is a security hazard).
  if wanted is None:
    return True
  if choices is None:
    return False
  for c in choices:
    if str_shim_eq(c, '^.*$'): # a regex matching all, matches all regexes/literals
      return True
    if len(wanted)<1 or str_shim_ne(wanted[0:1],'^'):
      # wanted is a literal
      if len(c) > 0 and str_shim_eq(c[0:1],'^'):
        r = re.compile(c)
        if r.match(wanted)!=None:
          return True
      elif str_shim_eq(wanted,c):
        return True
    else:
      # wanted is a regex
      if str_shim_eq(wanted,c):
        return True
  # went through all possibilities, did not find it
  return False

def intersect_multimatch(set1, set2):
  if set1==None:
    return set2
  if set2==None:
    return set1
  rv = []
  for w in set2:
    if multimatch(w,set1):
      rv.append(w)
  return rv

def validate_poison(name, value, pk):
  # validate that poison allows the given value for the specified
  # condition (name). It is valid if:
  #   1. Name or value is None. [OR]
  #   2. Name is in poison, not on the exception list, 
  #      and value multimatches that condition. [OR]
  #   3. Name is on the exception list, and values matches
  #      as specified for that exception.
  # Otherwise, the condition is invalid and this returns False.
  # Exceptions:
  #   1. Name = "pathlen": valid if pathlen not in poison array,
  #      or if in poison array and value<=that in poison array.
  #
  if name is None or value is None:
    return True
  poison = msgpack.unpackb(pk[1],raw=True)
  for ku in poison:
    if str_shim_eq(ku[0],name):
      if str_shim_ne(name,'pathlen') and multimatch(value,ku[1]):
        return True
      elif str_shim_eq(name,'pathlen') and value<=ku[1]:
        return True
      else:
        return False
  if str_shim_eq(name,'pathlen'):
    return True
  return False

def intersect_certs(c1, c2, same_pk):
  # main logic for determining the minimum allowed values consistent
  # with c1 and c2's constraints. Returns an array with the same
  # structure as a chain entry, with 0,1 set as the intersection of
  # c1 and c2, and values 2:...end set from c2
  # To avoid footguns, we make sure to enforce the following
  # additional conditions:
  # 1. If an item in the chain has key-allowlist or key-denylist, it is
  #    also assumed to imply pathlen = 0, unless explicitly overridden.
  pk = []
  if (c2[0] > 0 and (c2[0]<c1[0] or c1[0] == 0)):
    pk.append(c2[0])
  else:
    pk.append(c1[0])
  poisons = [[-1,msgpack.unpackb(c1[1],raw=True)], [0,msgpack.unpackb(c2[1],raw=True)]]
  if same_pk:
    poisons = [[0,msgpack.unpackb(c1[1],raw=True)], [0,msgpack.unpackb(c2[1],raw=True)]]
  poison_topics = None
  poison_usages = None
  pathlen = None
  for p in poisons:
    pathlen_offset = p[0]
    poison = p[1]
    new_pathlen = None
    for ku in poison:
      if str_shim_eq(ku[0],'topics'):
        poison_topics = intersect_multimatch(poison_topics, ku[1])
      elif str_shim_eq(ku[0],'usages'):
        if (multimatch('key-allowlist',ku[1]) or multimatch('key-denylist',ku[1])) and new_pathlen is None:
          # enforce zero pathlength unless overridden in this poison array
          new_pathlen = 0
        poison_usages = intersect_multimatch(poison_usages, ku[1])
      elif str_shim_eq(ku[0],'pathlen'):
        new_pathlen = ku[1]
      else:
        raise ValueError("Unknown chain signature poison")
    if new_pathlen!=None and (pathlen is None or (new_pathlen+pathlen_offset)<pathlen):
      pathlen = new_pathlen+pathlen_offset
  # Build new poison array
  poison = []
  if poison_topics!=None:
    poison.append(['topics',poison_topics])
  if poison_usages!=None:
    poison.append(['usages',poison_usages])
  if pathlen!=None:
    poison.append(['pathlen',pathlen])
  pk.append(msgpack.packb(poison, use_bin_type=True))
  # Copy entries 2-infinity
  pk = pk + c2[2:]
  return pk

def printable_cert(cert):
  #
  # Convert a certificate to a human-readable format
  #
  rv = []
  try:
    if isinstance(cert[2],(list,tuple)):
      for key in cert[2]:
        rv.append("Key: " + key.hex())
    else:
      rv.append("Key: " + cert[2].hex())
    rv.append("Timestamp: " + str(cert[0]))
    rv.append("Poison: " + str(msgpack.unpackb(cert[1],raw=True)))
  except:
    rv.append("Could not parse!")
    rv.append(str(cert))
  return rv

def process_chain(chain, topic=None, usage=None, allowlist=None, denylist=None):
  #
  # chain should be a single msgpack array, with the next item in the array
  # signed by the entity with public key given in the current item. The first
  # item must be signed by a root of trust (which are given in allowlist). 
  # Each (signed) item is itself a msgpack array containing:
  # (0) a max_age timestamp (64-bit unsigned unix maximum time signature is valid)
  # (1) a poison array. Sets allowed signature key usages, topics, pathlengths.
  # (2) public key
  # Possibly more items in (3)+, especially common for the final item,
  # but not needed to check the chain.
  #
  # Raises a ValueError if chain does not match topic or usage criteria, or
  # uses a denylisted key, unless there is ultimately a chain between
  # an allowlisted key and the final item with no denylisted keys.
  # The final item might itself be the allowlisted key.
  #
  # Otherwise, returns an array containing two arrays. The first array
  #  contains:
  #  (0) The minimum max_age timestamp
  #  (1) The intersection of allowed topics and usages, in the
  #      poison array (i.e. the net allowed topics and usages)
  #  (2) The public key
  #  And any items in (3)+ from the final item.
  # The second array contains one entry per item in the chain, containing
  # a textual / human readable description (useful for verbose messages) of
  # how the item was interpreted.
  #
  printable = []
  if allowlist is None:
    raise ProcessChainError("No possible roots of trust!", printable)
  last_error = ProcessChainError("No roots of trust found!", printable)
  for rot in allowlist:
    printable = []
    try:
      denylisted = False
      val = [rot] + msgpack.unpackb(chain,raw=True)
      if len(val) < 2:
        # must be validating at least one chain item beyond the item from the allowlist
        raise ValueError("Chain too short!")
      pk = None
      for npk in val:
        if not (pk is None):
          if key_in_list(pk[2],denylist)!=None:
            denylisted = True
            logging.warning("Chain uses denylisted signing key %s.",pk[2].hex())
            # this is not immediately fatal because a subkey might be allowlisted
          elif key_in_list(pk[2],allowlist)!=None:
            # allowlisted subkey overrides denylist
            denylisted = False
            pk = intersect_certs(pk,msgpack.unpackb(key_in_list(pk[2],allowlist),raw=True),True)
          try:
            pk = intersect_certs(pk,msgpack.unpackb(pysodium.crypto_sign_open(npk,pk[2]),raw=True),False)
          except:
            raise ValueError("Invalid signing!")
        else:
          pk = msgpack.unpackb(npk,raw=True) # root is unsigned
        printable.append(str(printable_cert(pk)))
      # must finally check if leaf key is in allowlist/denylist
      if key_in_list(pk[2],allowlist)!=None:
        denylisted = False
      if key_in_list(pk[2],denylist)!=None:
        denylisted = True
      # make sure our chain doesn't have breaking denylisted keys
      if denylisted:
        raise ValueError("Chain uses denylisted public key")
      # ensure composite chain is valid
      if (pk[0]<time() and pk[0]!=0):
        raise ValueError("Expired Chain!")
      if not validate_poison('topics',topic,pk):
        raise ValueError("No matching topic in allowed intersection set.")
      if not validate_poison('usages',usage,pk):
        raise ValueError("No matching usage in allowed intersection set.")
      if not validate_poison('pathlen',0,pk):
        raise ValueError("Exceeded allowed pathlen.")
      return [pk,printable]
    except ValueError as e:
      printable.append(str(e))
      last_error = ProcessChainError("Error during Validation:", printable)
  # We allow a key to self-sign itself to be denylisted. This enables any private
  # key to denylist itself
  try:
    chain = msgpack.unpackb(chain,raw=True)
    if len(chain) == 2:
      pk = msgpack.unpackb(chain[0],raw=True)
      pk0 = pk[2]
      pk = intersect_certs(pk,msgpack.unpackb(pysodium.crypto_sign_open(chain[1],pk[2]),raw=True),False)
      if pk0 == pk[2] and multimatch(usage, ['key-denylist']) and validate_poison('usages','key-denylist',pk) and validate_poison('pathlen',0,pk):
        return [pk,[str(printable_cert(pk))]]
  except:
    pass
  raise last_error
