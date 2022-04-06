import pysodium
import msgpack
from hashlib import sha256
from os import replace, remove, fsync as osfsync, open as osopen, close as osclose
from os.path import dirname, normpath
from shutil import copy, copymode
from base64 import b64encode, b64decode
from binascii import unhexlify, hexlify, Error as binasciiError
from time import time
from kafkacrypto.exceptions import KafkaCryptoUtilError
from traceback import format_exception

# *nix specific items
try:
    import fcntl

    # We need to be able to exclusively lock a file in the implementation of
    # AtomicWriter here. Takes as input a file descriptor.
    def exclusive_lock(fh):
        fcntl.lockf(fh.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB) # Locks entire file exclusively
    def exclusive_unlock(fh):
        fcntl.lockf(fh.fileno(),fcntl.LOCK_UN) # Unlock file exclusively

    # See https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html
    # Need F_FULLFSYNC on OS X / iOS to actually flush everything
    if hasattr(fcntl, 'F_FULLFSYNC'):
        def osfsync(fd):
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
except ImportError:
    pass

# Windows specific items
try:
    import msvcrt
    from os import fstat as osfstat

    # We need to be able to exclusively lock a file in the implementation of
    # AtomicWriter here. Takes as input a file descriptor.
    # Per:
    #   https://bugs.python.org/issue29392
    #   https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/locking?view=msvc-170
    # We have to find out the size of the file to lock all of it. But for
    # a file being written to, its size might be different at lock time than unlock time.
    # We can, however, lock past the end of file. So lock the maximum amount we can (2^31-1),
    # and unlock the same. We also have to make sure the lock starts from the beginning of the file.
    def exclusive_lock(fh):
        pos = fh.tell()
        fh.seek(0)
        msvcrt.locking(fh.fileno(),msvcrt.LK_NBLCK,2147483647) # Locks entire file exclusively
        fh.seek(pos)
    def exclusive_unlock(fh):
        pos = fh.tell()
        fh.seek(0)
        msvcrt.locking(fh.fileno(),msvcrt.LK_UNLCK,2147483647) # Unlock file exclusively
        fh.seek(pos)
except ImportError:
    pass

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
     Because multiple writes can be bunched and then committed atomically, we are
     required to be the only process reading or writing the file (a more elaborate
     implementation could elide this requirement, but is not needed in KafkaCrypto).

     There is a known race condition where there are brief windows in time (during
     the flush operation) when another process could swoop in and take over access.
     However, this will be "noisy" as then the exlusive lock request at the end
     of the flush will fail. So it achieves the needed guarantee here: at most one
     AtomicFile object is associated with a given file at a time.

     It IS NOT thread safe.
  """
  def __init__(self, file, binary=False, tmpfile=None):
    if tmpfile==None:
      tmpfile = file + ".tmp"
    self.__file = file
    self.__filedir = normpath(dirname(file))
    self.__binary = binary
    if not binary:
      self.__fm = "r+"
    else:
      self.__fm = "rb+"
    self.__tmpfile = tmpfile
    # Readfile is only used for reading. However, to enable exclusive access, we
    # must actually open it for writing too
    self.__readfile = self.internal_open(self.__file, self.__fm)
    # Writefile is only used for writing. However, to keep read/write consistency,
    # we must open it for both reading and writing
    self.__writefile = None

  def internal_open(self, *args, **kwargs):
    rv = open(*args, **kwargs)
    exclusive_lock(rv)
    return rv

  def internal_close(self, ofo):
    exclusive_unlock(ofo)
    return ofo.close()

  def seek(self, *args, **kwargs):
    if self.__writefile != None:
      self.__writefile.seek(*args, **kwargs)
    return self.__readfile.seek(*args, **kwargs)

  def write(self, *args, **kwargs):
    if self.__writefile == None:
      exclusive_unlock(self.__readfile)
      copy(self.__file, self.__tmpfile)
      exclusive_lock(self.__readfile)
      self.__writefile = self.internal_open(self.__tmpfile, self.__fm)
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
      exclusive_unlock(self.__readfile)
      copy(self.__file,	self.__tmpfile)
      exclusive_lock(self.__readfile)
      self.__writefile = self.internal_open(self.__tmpfile, self.__fm)
      self.__writefile.seek(self.__readfile.tell(),0)
    return self.__writefile.truncate(**kwargs)

  def flush_dir(self):
    try:
      fd = osopen(self.__filedir, 0)
      try:
        osfsync(fd)
      finally:
        osclose(fd)
    except PermissionError:
      pass # Ignorable since it just means atomic operation may take longer to complete (but still atomic)
           # Happens on Windows

  def flush(self):
    if self.__writefile != None:
      # flush written data to temporary file
      rv = self.__writefile.flush()
      # preserve current file read/write position to restore later
      pos = self.__writefile.tell()
      # sync and close reader and writer handles
      self.internal_close(self.__readfile)
      osfsync(self.__writefile.fileno())
      self.internal_close(self.__writefile)
      # copy file permissions, etc, to tmpfile, in preparation for atomic replace
      # both files are closed, so no exlusive locks to release first
      copymode(self.__file, self.__tmpfile)
      # the atomic operation
      # atomic on python 3.3+ on POSIX
      # atomic on python 3.3+ on Windows NT if filesystem supports atomic moves
      #   https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/449bb49d-8acc-48dc-a46f-0760ceddbfc3/movefileexmovefilereplaceexisting-ntfs-same-volume-atomic?forum=windowssdk#a239bc26-eaf0-4920-9f21-440bd2be9cc8
      #   https://github.com/python/cpython/blob/main/Modules/posixmodule.c#L4728
      replace(self.__tmpfile, self.__file)
      # The above is atomic, but not necessarily committed until the containing directory's metadata is updated.
      # (which is not guaranteed on windows NT since MOVEFILE_WRITE_THROUGH is not passed in Pythons replace implementation, and not guaranteed on POSIX either)
      # Issue the directory fsync to commit it here.
      self.flush_dir()
      # reopen for reading, restoring read pointer location
      self.__readfile = self.internal_open(self.__file, self.__fm)
      self.__readfile.seek(pos,0)
      self.__writefile = None
      return rv
    else:
      remove(self.__tmpfile)
      return None

  def close(self):
    self.flush()
    return self.internal_close(self.__readfile)

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
