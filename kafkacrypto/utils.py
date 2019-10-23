import pysodium
import msgpack
from os import replace, remove
from shutil import copymode
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify, Error as binasciiError
from time import time
from kafkacrypto.exceptions import KafkaCryptoUtilError

def str_decode(value, iskey=False):
  if value!=None:
    try:
      value = int(value)
    except ValueError as e:
      try:
        value = float(value)
      except ValueError as e:
        if value.lower() == "true":
          value = True 
        elif value.lower() == "false":
          value = False
        elif value.startswith("base64#"):
          try:
            value = b64decode(value[7:].encode('utf-8'),validate=True)
          except binasciiError:
            value = None
        elif iskey:
          # case insensitive keys
          value = value.lower()
  elif default!=None:
    return default
  return value

def str_encode(value, iskey=False):
  if value!=None:
    if isinstance(value,(int,float,bool)):
      value = str(value)
    if not isinstance(value,(str,)):
      value = 'base64#' + b64encode(value).decode('utf-8')
    elif iskey:
      # case insensitive keys
      value = value.lower()
  return value

class ShadowFile(object):
  """The ShadowFile class instantiates a very simplistic file with atomic semantics
     for write and flush commands (nothing is written until flush is issued, then all
     or nothing is written). It IS NOT thread safe.
  """
  def __init__(self, file):
    self.__file = file
    self.__readfile = open(file, "r")
    self.__writefile = open(file + ".tmp", "w")

  def seek(self, *args, **kwargs):
    self.__writefile.seek(*args, **kwargs)
    return self.__readfile.seek(*args, **kwargs)

  def write(self, *args, **kwargs):
    return self.__writefile.write(*args, **kwargs)

  def writelines(self, *args, **kwargs):
    return self.__writefile.write(*args, **kwargs)

  def truncate(self, **kwargs):
    return self.__writefile.truncate(**kwargs)

  def flush(self):
    # the atomic operation
    rv = self.__writefile.flush()
    self.__readfile.close()
    self.__writefile.close()
    copymode(self.__file, self.__file + ".tmp")
    replace(self.__file + ".tmp", self.__file) # atomic on python 3.3+
    self.__readfile = open(self.__file, "r")
    self.__writefile = open(self.__file + ".tmp", "w")
    return rv

  def close(self):
    self.flush()
    self.__writefile.close()
    remove(self.__file + ".tmp")
    return self.__readfile.close()

  def __iter__(self):
    return self.__readfile.__iter__()

  def __next__(self):
    return self.__readfile.__next__()

  def __getattr__(self, name):
    def method(*args, **kwargs):
      return self.__readfile.getattr(name)(*args, **kwargs)
    
def atomic_open(file, **kwargs):
  if len(kwargs) > 0:
    raise ValueError("Not Supported!")
  return ShadowFile(file)

class PasswordProvisioner(object):
  """The PasswordProvisioner class instantiates three provisioner keys, and uses them
  to sign signing keys of new producers/consumers.

  Alternative versions using, e.g. security keys or similar, can also be written.

  Keyword Arguments:
  password (str): Password from which to derive the provisioning secret keys.

  """
  # Constrained devices cannot use larger numbers than interactive
  _ops = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  _mem = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  def __init__(self, password, rot):
    if (isinstance(password,(str,))):
      password = password.encode('utf-8')
    try:
      rot = unhexlify(rot)
    except:
      pass
    self._salt = {}
    self._salt['producer'] = pysodium.crypto_hash_sha256(b'producer' + rot)[0:pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES]
    self._salt['consumer'] = pysodium.crypto_hash_sha256(b'consumer' + rot)[0:pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES]
    self._salt['prodcon'] = pysodium.crypto_hash_sha256(b'prodcon' + rot)[0:pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES]
    self._seed = {}
    self._pk = {}
    self._sk = {}
    print("")
    print("Deriving provisioning keys with:")
    print("  opsl = ", self._ops)
    print("  meml = ", self._mem)
    for key in self._salt.keys():
      print("  salt (", key, ") = ", hexlify(self._salt[key]))
      self._seed[key] = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES, password, self._salt[key], opslimit=self._ops, memlimit=self._mem)
      self._pk[key], self._sk[key] = pysodium.crypto_sign_seed_keypair(self._seed[key])
      print("  Signing Public Key (", key, "): ", hexlify(self._pk[key]))
    print("")

class PasswordROT(object):
  """The PasswordROT class instantiates a root of trust keypair.

  Alternative versions using, e.g. security keys or similar, can also be written.

  Keyword Arguments:
  password (str): Password from which to derive the secret key.
  """
  # Constrained devices cannot use larger numbers than interactive
  _ops = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
  _mem = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

  def __init__(self, password):
    if (isinstance(password,(str,))):
      password = password.encode('utf-8')
    self._salt = pysodium.crypto_hash_sha256(b'Root of Trust' + password)[0:pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES]
    print("")
    print("Deriving root key with:")
    print("  opsl = ", self._ops)
    print("  meml = ", self._mem)
    print("  salt = ", hexlify(self._salt))
    self._seed = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES, password, self._salt, opslimit=self._ops, memlimit=self._mem)
    self._pk, self._sk = pysodium.crypto_sign_seed_keypair(self._seed)
    print("  Root Public Key: ", hexlify(self._pk))
    print("")
