from time import time
import pysodium
import msgpack
import logging
import re

def key_in_list(wanted, choices):
  # choices is an array of zero or more msgpacked arrays, each of
  # which has the format of a chain entry (see below). This helper
  # function iterates each choice, seeing if the key wanted
  # is present, and returns the match (if any)
  if wanted is None or choices is None:
    return None
  for c in choices:
    pk = msgpack.unpackb(c)
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
  #     choices.
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
    if len(wanted)<1 or (wanted[0] != b'^'[0] and wanted[0] != '^'):
      # wanted is a literal
      if len(c) > 0 and (c[0] == b'^'[0] or c[0] == '^'):
        r = re.compile(c)
        if r.match(wanted)!=None:
          return True
      elif wanted == c:
        return True
    else:
      # wanted is a regex
      if wanted == c:
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
  poison = msgpack.unpackb(pk[1])
  for ku in poison:
    if ku[0] == name:
      if name != b'pathlen' and multimatch(value,ku[1]):
        return True
      elif name == b'pathlen' and value<=ku[1]:
        return True
      else:
        return False
  if name == b'pathlen':
    return True
  return False

def intersect_certs(c1, c2):
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
  poisons = [[-1,msgpack.unpackb(c1[1])], [0,msgpack.unpackb(c2[1])]]
  poison_topics = None
  poison_usages = None
  pathlen = None
  for p in poisons:
    pathlen_offset = p[0]
    poison = p[1]
    new_pathlen = None
    for ku in poison:
      if (ku[0] == b'topics'):
        poison_topics = intersect_multimatch(poison_topics, ku[1])
      elif (ku[0] == b'usages'):
        if (multimatch(b'key-allowlist',ku[1]) or multimatch(b'key-denylist',ku[1])) and new_pathlen is None:
          # enforce zero pathlength unless overridden in this poison array
          new_pathlen = 0
        poison_usages = intersect_multimatch(poison_usages, ku[1])
      elif (ku[0] == b'pathlen'):
        new_pathlen = ku[1]
      else:
        raise ValueError("Unknown chain signature poison")
    if new_pathlen!=None and (pathlen is None or (new_pathlen+pathlen_offset)<pathlen):
      pathlen = new_pathlen+pathlen_offset
  # Build new poison array
  poison = []
  if poison_topics!=None:
    poison.append([b'topics',poison_topics])
  if poison_usages!=None:
    poison.append([b'usages',poison_usages])
  if pathlen!=None:
    poison.append([b'pathlen',pathlen])
  pk.append(msgpack.packb(poison))
  # Copy entries 2-infinity
  pk = pk + c2[2:]
  return pk

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
  # Returns a ValueError if chain does not match topic or usage criteria, or
  # uses a denylisted key, unless there is ultimately a chain between
  # an allowlisted key and the final item with no denylisted keys.
  # The final item might itself be the allowlisted key.
  #
  # Otherwise, returns an array containing:
  # (0) The minimum max_age timestamp
  # (1) The intersection of allowed topics and usages, in the
  #     poison array (i.e. the net allowed topics and usages)
  # (2) The public key
  # And any items in (3)+ from the final item.
  #
  if allowlist is None:
    raise ValueError("No possible roots of trust!")
  last_error = ValueError("No roots of trust found!")
  for rot in allowlist:
    try:
      denylisted = False
      val = [rot] + msgpack.unpackb(chain)
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
            pk = intersect_certs(pk,msgpack.unpackb(key_in_list(pk[2],allowlist)))
          try:
            pk = intersect_certs(pk,msgpack.unpackb(pysodium.crypto_sign_open(npk,pk[2])))
          except:
            raise ValueError("Invalid signing!")
        else:
          pk = msgpack.unpackb(npk) # root is unsigned
      # must finally check if leaf key is in allowlist, which overrides any denylist entries
      if key_in_list(pk[2],allowlist)!=None:
        denylisted = False
      # make sure our chain doesn't have breaking denylisted keys
      if denylisted:
        raise ValueError("Chain uses denylisted public key")
      # ensure composite chain is valid
      if (pk[0]<time() and pk[0]!=0):
        raise ValueError("Expired Chain!")
      if not validate_poison(b'topics',topic,pk):
        raise ValueError("No matching topic in allowed intersection set.")
      if not validate_poison(b'usages',usage,pk):
        raise ValueError("No matching usage in allowed intersection set.")
      if not validate_poison(b'pathlen',0,pk):
        raise ValueError("Exceeded allowed pathlen.")
      return pk
    except ValueError as e:
      last_error = e
  # We allow a key to self-sign itself to be denylisted. This enables any private
  # key to denylist itself
  try:
    chain = msgpack.unpackb(chain)
    if len(chain) == 2:
      pk = msgpack.unpackb(chain[0])
      pk0 = pk[2]
      pk = intersect_certs(pk,msgpack.unpackb(pysodium.crypto_sign_open(chain[1],pk[2])))
      if pk0 == pk[2] and multimatch(usage, [b'key-denylist']) and validate_poison(b'usages',b'key-denylist',pk) and validate_poison(b'pathlen',0,pk):
        return pk
  except:
    pass
  raise last_error
