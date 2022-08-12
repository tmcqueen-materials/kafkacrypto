import msgpack
import pysodium
try:
  # until more mature implementations are available, use Open Quantum Safe
  import oqs
except ImportError:
  pass

class PublicKeyError(Exception):
  """
  Error converting to a public key
  """

class SecretKeyError(Exception):
  """
  Error converting to a secret key
  """

def get_pks(pk0):
  if isinstance(pk0, (SignPublicKey,KEMPublicKey)):
    return pk0
  elif isinstance(pk0, (list,tuple)):
    if isinstance(pk0[0], (int,)): # versioned
      try:
        return SignPublicKey(pk0)
      except PublicKeyError:
        return KEMPublicKey(pk0)
    else:
      # list of public keys
      rv = []
      for pk in pk0:
        rv.append(get_pks(pk))
      return rv
  else:
    # implicit version 1, treat as sign public key for now
    return SignPublicKey([1, pk0])

# Public keys used for signing.
# version is an integer that determines the meaning of keys.
#  --> except version 1, values should be unique between Sign and KEM classes
# version   keys
# -------   -------
#    1      bytes representing an Ed25519 public key
class SignPublicKey(object):
  version = 0
  keys = b''
  def __init__(self, pk0):
    if isinstance(pk0, (SignPublicKey,)):
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (list,tuple)):
      if isinstance(pk0[0], (int,)) and pk0[0] == 1: # currently only version 1 supported
        self.version = pk0[0]
        self.keys = pk0[1]
      else:
        # list of public keys
        raise PublicKeyError()
    else:
      # implicit version 1
      self.version = 1
      self.keys = pk0
    # for ctypes calling compatibility (see also __len__ and __getitem__ below)
    self._as_parameter_ = bytes(self)
  def __bytes__(self):
    if self.version == 1:
      return self.keys
    else:
      return msgpack.packb([self.version, self.keys],use_bin_type=True)
  def __str__(self):
    if self.version == 1:
      return "(Ed25519, " + self.keys.hex() + ")"
    else:
      return "(Unparsable)"
  def __eq__(self, pk2):
    if isinstance(pk2, (SignPublicKey,)) and self.version == pk2.version:
      if self.version == 1 and self.keys == pk2.keys:
        return True
    return False
  def __len__(self):
    return len(self._as_parameter_)
  def __getitem__(self, index):
    return self._as_parameter_[index]
  def __iter__(self):
    return iter([self.version, self.keys])
  def msgpack_pack(self):
    if self.version == 1:
      return self.keys
    else:
      return list(self)
  def crypto_sign_open(self, cso):
    if self.version == 1:
      return pysodium.crypto_sign_open(cso,self.keys)
    raise PublicKeyError

# Public keys used for key exchange.
# version is an integer that determines the meaning of keys.
#  --> except version 1, values should be unique between Sign and KEM classes
# version   keys
# -------   -------
#    1      bytes representing an Curve25519 public key
#    2      list of two items: Curve25519 pk bytes, sntrup761 pk bytes
#    3      list of two items: Curve25519 pk bytes, sntrup761 ct bytes
class KEMPublicKey(object):
  version = 0
  keys = b''
  def __init__(self, pk0):
    if isinstance(pk0, (SignPublicKey,)) and pk0.version == 1: # we allow conversion of implicit version 1 keys between Sign and KEM types
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (KEMPublicKey,)):
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (KEMSecretKey,)): # generating public key from secret key is allowed
      if pk0.version == 3:
        self.version = 3
        # compute Curve25519 public key in situ, include sntrup761 encapped ciphertext
        self.keys = [pysodium.crypto_scalarmult_curve25519_base(pk0.keys[0]),pk0.keys[1][2]]
      elif pk0.version == 2:
        self.version = 2
        # compute Curve25519 public key in situ, include sntrup761 public key
        self.keys = [pysodium.crypto_scalarmult_curve25519_base(pk0.keys[0]),pk0.keys[1][1]]
      else:
        # default version 1
        self.version = 1
        self.keys = pysodium.crypto_scalarmult_curve25519_base(pk0.keys)
    elif isinstance(pk0, (list,tuple)):
      if isinstance(pk0[0], (int,)) and (pk0[0] == 1 or pk0[0] == 2 or pk0[0] == 3): # Versions 1-3 only
        self.version = pk0[0]
        self.keys = pk0[1]
      else:
        # list of public keys
        raise PublicKeyError()
    else:
      # implicit version 1
      self.version = 1
      self.keys = pk0
    # for ctypes calling compatibility (see also __len__ and __getitem__ below)
    self._as_parameter_ = bytes(self)
  def __bytes__(self):
    if self.version == 1:
      return self.keys
    else:
      return msgpack.packb([self.version, self.keys],use_bin_type=True)
  def __str__(self):
    if self.version == 1:
      return "(Curve25519-pk, " + self.keys.hex() + ")"
    elif self.version == 2:
      return "(Curve25519-sntrup761-pk, [" + self.keys[0].hex() + "," + self.keys[1].hex() + "])"
    elif self.version == 3:
      return "(Curve25519-sntrup761-ct, [" + self.keys[0].hex() + "," + self.keys[1].hex() + "])"
    else:
      return "(Unparsable)"
  def __eq__(self, pk2):
    if isinstance(pk2, (KEMPublicKey,)) and self.version == pk2.version:
      if self.version == 1 and self.keys == pk2.keys:
        return True
      elif (self.version == 2 or self.version == 3) and self.keys[0] == pk2.keys[0] and self.keys[1] == pk2.keys[1]:
        return True
    return False
  def __len__(self):
    return len(self._as_parameter_)
  def __getitem__(self, index):
    return self._as_parameter_[index]
  def __iter__(self):
    return iter([self.version, self.keys])
  def get_esk_version(self):
    if self.version == 3:
      return 2
    else:
      return self.version
  def msgpack_pack(self):
    if self.version == 1:
      return self.keys
    else:
      return list(self)

# Secret keys used for key exchange.
# version is an integer that determines the meaning of keys.
#  --> should have the same versions as KEMPublicKey
# version   keys
# -------   -------
#    1      bytes representing an Curve25519 secret key
#   2,3     list of two items: Curve25519 bytes, sntrup761 bytes list [sk,pk,ct (v. 3 only)]
class KEMSecretKey(object):
  version = 0
  keys = b''
  def __init__(self, pk0):
    if isinstance(pk0, (KEMSecretKey,)):
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (list,tuple)):
      if isinstance(pk0[0], (int,)) and (pk0[0] == 1 or pk0[0] == 2 or pk0[0] == 3): # versions 1-3 only
        self.version = pk0[0]
        self.keys = pk0[1]
        if self.version == 2 or self.version == 3:
          self.sntrup761 = oqs.KeyEncapsulation("sntrup761", secret_key=self.keys[1][0])
      else:
        # list of secret keys
        raise SecretKeyError()
    elif isinstance(pk0,(bytes,bytearray)) and len(pk0) == 32:
      # implicit version 1
      self.version = 1
      self.keys = pk0
    else:
      # assume version is what was passed
      if pk0 == 3:
        raise SecretKeyError() # cannot create type-3 directly, requires a complete_kem call
      elif pk0 == 2:
        self.version = 2
        self.keys = [pysodium.randombytes(pysodium.crypto_scalarmult_curve25519_BYTES)] # Curve25519 key first
        self.sntrup761 = oqs.KeyEncapsulation("sntrup761")
        pk = self.sntrup761.generate_keypair()
        self.keys += [[self.sntrup761.export_secret_key(),pk]] # sntrup761 key second (store both secret and public key)
      else:
        # default to version 1
        self.version = 1
        self.keys = pysodium.randombytes(pysodium.crypto_scalarmult_curve25519_BYTES)
    # for ctypes calling compatibility (see also __len__ and __getitem__ below)
    self._as_parameter_ = bytes(self)
  def __bytes__(self):
    if self.version == 1:
      return self.keys
    else:
      return msgpack.packb([self.version, self.keys],use_bin_type=True)
  def __str__(self):
    if self.version == 1:
      return "(Curve25519-Secret, " + self.keys.hex() + ")"
    elif self.version == 2:
      return "(Curve25519-sntrup761-Secret, [" + self.keys[0].hex() + ",[" + self.keys[1][0].hex() + "," + self.keys[1][1].hex() + "]])"
    elif self.version == 3:
      return "(Curve25519-sntrup761-Secret-ct, [" + self.keys[0].hex() + ",[" + self.keys[1][0].hex() + "," + self.keys[1][1].hex() + "," + self.keys[1][2].hex() + "]])"
    else:
      return "(Unparsable)"
  def __eq__(self, pk2):
    if isinstance(pk2, (KEMSecretKey,)) and self.version == pk2.version:
      if self.version == 1 and self.keys == pk2.keys:
        return True
      elif self.version == 2 and self.keys[0] == pk2.keys[0] and self.keys[1][0] == pk2.keys[1][0] and self.keys[1][1] == pk2.keys[1][1]:
        return True
      elif self.version == 3 and self.keys[0] == pk2.keys[0] and self.keys[1][0] == pk2.keys[1][0] and self.keys[1][1] == pk2.keys[1][1] and self.keys[1][2] == pk2.keys[1][2]:
        return True
    return False
  def __len__(self):
    return len(self._as_parameter_)
  def __getitem__(self, index):
    return self._as_parameter_[index]
  def __iter__(self):
    return iter([self.version, self.keys])
  def msgpack_pack(self):
    if self.version == 1:
      return self.keys
    else:
      return list(self)
  def complete_kem(self, pubkey):
    if self.version == 1 and pubkey.version == 1:
      return pysodium.crypto_scalarmult_curve25519(self.keys,pubkey.keys)
    elif (self.version == 2 or self.version == 3) and pubkey.version == 2:
      part0 = pysodium.crypto_scalarmult_curve25519(self.keys[0],pubkey.keys[0])
      ct, part1 = self.sntrup761.encap_secret(pubkey.keys[1])
      if self.version == 2:
        self.version = 3
        self.keys[1].append(ct)
      else: # self.version is already 3
        self.keys[1][2] = ct
      return part0 + part1
    elif self.version == 2 and pubkey.version == 3: # cannot do 3 with 3 since we don't have partner pk
      part0 = pysodium.crypto_scalarmult_curve25519(self.keys[0],pubkey.keys[0])
      part1 = self.sntrup761.decap_secret(pubkey.keys[1])
      return part0 + part1
    else:
      raise SecretKeyError()
