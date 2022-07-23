import msgpack
import pysodium

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
      if isinstance(pk0[0], (int,)):
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
class KEMPublicKey(object):
  version = 0
  keys = b''
  def __init__(self, pk0):
    if isinstance(pk0, (KEMPublicKey,SignPublicKey)): # we allow conversion of implicit version 1 keys between Sign and KEM types
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (list,tuple)):
      if isinstance(pk0[0], (int,)):
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
      return "(Curve25519, " + self.keys.hex() + ")"
    else:
      return "(Unparsable)"
  def __eq__(self, pk2):
    if isinstance(pk2, (KEMPublicKey,)) and self.version == pk2.version:
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

# Secret keys used for key exchange.
# version is an integer that determines the meaning of keys.
#  --> should have the same versions as KEMPublicKey
# version   keys
# -------   -------
#    1      bytes representing an Curve25519 secret key
class KEMSecretKey(object):
  version = 0
  keys = b''
  def __init__(self, pk0):
    if isinstance(pk0, (KEMSecretKey,SignPublicKey)): # we allow conversion of implicit version 1 keys between Sign and KEM types
      self.version = pk0.version
      self.keys = pk0.keys
    elif isinstance(pk0, (list,tuple)):
      if isinstance(pk0[0], (int,)):
        self.version = pk0[0]
        self.keys = pk0[1]
      else:
        # list of secret keys
        raise SecretKeyError()
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
      return "(Curve25519-Secret, " + self.keys.hex() + ")"
    else:
      return "(Unparsable)"
  def __eq__(self, pk2):
    if self.version == pk2.version:
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
  def complete_kem(self, pubkey):
    if self.version == 1 and pubkey.version == 1:
      return pysodium.crypto_scalarmult_curve25519(self.keys,pubkey.keys)
