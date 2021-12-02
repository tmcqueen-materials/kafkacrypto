import pysodium
import msgpack
from hashlib import sha256
from os import replace, remove, fsync
from shutil import copy, copymode
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify, Error as binasciiError
from time import time
from kafkacrypto.exceptions import KafkaCryptoUtilError
from traceback import format_exception

# Shim for Python 3.10+ compatibility
def format_exception_shim(exc=None, **kwargs):
    try:
        # Python < 3.10
        return format_exception(etype=type(exc), value=exc, tb=exc.__traceback__, **kwargs)
    except:
        try:
            # Python >= 3.10
            return format_exception(exc, **kwargs)
        except:
            # Catch any errors to avoid management thread dying
            return ["Could not format exception.\n"]

# Useful for log rate limiting
log_limited_map = {}
def log_limited(logfunc, msg, *args, msg_id=None, limit_time=10, **kwargs):
    global log_limited_map
    if msg_id is None:
        msgh = msg
        if isinstance(msgh, (str,)):
            msgh = msgh.encode('utf-8')
        msg_id = sha256(msgh).digest()
    if not (msg_id in log_limited_map) or log_limited_map[msg_id]+limit_time <= time():
        log_limited_map[msg_id] = time()
        logfunc(msg, *args, **kwargs)

def str_shim_eq(v, lit):
  if isinstance(v,(bytes,bytearray)):
    v = v.decode('utf-8')
  if isinstance(lit,(bytes,bytearray)):
    lit = lit.decode('utf-8')
  if v == lit:
    return True
  return False

def str_shim_ne(v, lit):
  if isinstance(v,(bytes,bytearray)):
    v = v.decode('utf-8')
  if isinstance(lit,(bytes,bytearray)):
    lit	= lit.decode('utf-8')
  if v != lit:
    return True
  return False

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

class AtomicFile(object):
  """The AtomicFile class instantiates a very simplistic file with atomic semantics.
     Nothing is written until flush is issued, then all or nothing is written).
     It IS NOT thread safe.
  """
  def __init__(self, file, binary=False, tmpfile=None):
    if tmpfile==None:
      tmpfile = file + ".tmp"
    self.__file = file
    self.__binary = binary
    if not binary:
      self.__fm = "r"
      self.__wfm = "r+"
    else:
      self.__fm = "rb"
      self.__wfm = "rb+"
    self.__tmpfile = tmpfile
    self.__readfile = open(self.__file, self.__fm)
    self.__writefile = None

  def seek(self, *args, **kwargs):
    if self.__writefile != None:
      self.__writefile.seek(*args, **kwargs)
    return self.__readfile.seek(*args, **kwargs)

  def write(self, *args, **kwargs):
    if self.__writefile == None:
      copy(self.__file, self.__tmpfile)
      self.__writefile = open(self.__tmpfile, self.__wfm)
      self.__writefile.seek(self.__readfile.tell(),0)
    return self.__writefile.write(*args, **kwargs)

  def writelines(self, lines):
    if self.__binary:
      combined = b''.join(lines)
    else:
      combined = ''.join(lines)
    return self.write(lines)

  def truncate(self, **kwargs):
    if self.__writefile == None:
      copy(self.__file,	self.__tmpfile)
      self.__writefile = open(self.__tmpfile, self.__wfm)
      self.__writefile.seek(self.__readfile.tell(),0)
    return self.__writefile.truncate(**kwargs)

  def flush(self):
    if self.__writefile != None:
      # the atomic operation
      rv = self.__writefile.flush()
      pos = self.__writefile.tell()
      self.__readfile.close()
      fsync(self.__writefile.fileno())
      self.__writefile.close()
      copymode(self.__file, self.__tmpfile)
      replace(self.__tmpfile, self.__file) # atomic on python 3.3+
      self.__readfile = open(self.__file, self.__fm)
      self.__readfile.seek(pos,0)
      self.__writefile = None
      return rv
    else:
      remove(self.__tmpfile)
      return None

  def close(self):
    self.flush()
    return self.__readfile.close()

  def __iter__(self):
    return self.__readfile.__iter__()

  def __next__(self):
    return self.__readfile.__next__()

  def __getattr__(self, name):
    return getattr(self.__readfile,name)

def atomic_open(file, mode='r', **kwargs):
  mode = kwargs.pop('mode', mode)
  if len(kwargs) > 0 or (mode.lower() != 'r+' and mode.lower() != 'rb+'):
    raise ValueError("Not Supported!")
  binary = False
  if mode.lower().find('b') != -1:
    binary = True
  return AtomicFile(file, binary=binary)

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
