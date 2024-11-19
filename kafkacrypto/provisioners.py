from time import time
from kafkacrypto.utils import format_exception_shim
import pysodium
import msgpack
import logging
from binascii import unhexlify, hexlify
from kafkacrypto.chain import process_chain, ProcessChainError
from kafkacrypto.keys import SignPublicKey, SignSecretKey

class Provisioners(object):
  """Class validating key requests

  Keyword Arguments:
         allowlist (array): List of allowlisted public keys (provisioners)
          denylist (array): Optional list of denylisted public keys
  """
  def __init__(self, allowlist=None, denylist=None):
    self._logger = logging.getLogger(__name__)
    self.__allowlist = allowlist
    self.__denylist = denylist

  def reencrypt_request(self, topic, cryptoexchange, msgkey=None, msgval=None):
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("topic provided as bytes (should be string)")
      topic = topic.decode('utf-8')
    #
    # msgval should be a msgpacked chain chaining to a provisioner.
    # The third item in the array is the public key to retransmit. The fourth item is
    # random0.
    #
    try:
      pk = None
      try:
        pk,pkprint,pktypes = process_chain(msgval,topic,'key-encrypt-subscribe',allowlist=self.__allowlist,denylist=self.__denylist)
      except ProcessChainError as pce:
        raise pce
      except:
        pass
      if (pk is None):
        if not (pkprint is None):
          raise ProcessChainError("Request did not validate: ", pkprint)
        else:
          raise ValueError("Request did not validate!")
      # TODO: can add sanity checking of random0 and the public key if desired.
      msgs = cryptoexchange.signed_epks(topic, epks=[pk[2]], random0=pk[3], matchpk=pktypes[0])
      if len(msgs) == 0: # did not match same key type, so use them all
        msgs = cryptoexchange.signed_epks(topic, epks=[pk[2]], random0=pk[3])
      # TODO: Handle more than one signing key.
      msg = msgs[0][0]
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return (None, None)
    return (msgkey, msg)

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

  def __init__(self, password, rot, keytype=1):
    if (isinstance(password,(str,))):
      password = password.encode('utf-8')
    try:
      rot = unhexlify(rot)
    except:
      pass
    rot = bytes(rot)
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
      if keytype == 1:
        self._seed[key] = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES, password, self._salt[key], opslimit=self._ops, memlimit=self._mem)
        self._pk[key], self._sk[key] = pysodium.crypto_sign_seed_keypair(self._seed[key])
        self._pk[key] = SignPublicKey(self._pk[key])
        self._sk[key] = SignSecretKey(self._sk[key])
        print("  Signing Public Key (", key, "): ", str(self._pk[key]))
      elif keytype == 4:
        # TODO: We also need a variant of pyspx to deterministically generate a keypair from a seed
        # until that capability is added to liboqs
        import pyspx_slhdsa.shake_128f
        self._seed[key] = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES+pyspx_slhdsa.shake_128f.crypto_sign_SEEDBYTES, password, self._salt[key], opslimit=self._ops, memlimit=self._mem) # first 32 bytes Ed25519, next 96 bytes SLH-DSA-SHAKE-128f
        pk1,sk1 = pysodium.crypto_sign_seed_keypair(self._seed[key][0:pysodium.crypto_sign_SEEDBYTES])
        pk2,sk2 = pyspx_slhdsa.shake_128f.generate_keypair(self._seed[key][pysodium.crypto_sign_SEEDBYTES:])
        self._pk[key] = SignPublicKey([4,[pk1,pk2]])
        self._sk[key] = SignSecretKey([4,[sk1,sk2]])
        print("  Signing Public Key (", key, "): ", str(self._pk[key]))
      else:
        raise NotImplementedError
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

  def __init__(self, password, keytype=1):
    if (isinstance(password,(str,))):
      password = password.encode('utf-8')
    self._salt = pysodium.crypto_hash_sha256(b'Root of Trust' + password)[0:pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES]
    print("")
    print("Deriving root key with:")
    print("  opsl = ", self._ops)
    print("  meml = ", self._mem)
    print("  salt = ", hexlify(self._salt))
    if keytype == 1:
      self._seed = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES, password, self._salt, opslimit=self._ops, memlimit=self._mem)
      self._pk, self._sk = pysodium.crypto_sign_seed_keypair(self._seed)
      self._pk = SignPublicKey(self._pk)
      self._sk = SignSecretKey(self._sk)
      print("  Root Public Key: ", str(self._pk))
    elif keytype == 4:
      # TODO: We also need a variant of pyspx to deterministically generate a keypair from a seed
      # until that capability is added to liboqs
      import pyspx_slhdsa.shake_128f
      self._seed = pysodium.crypto_pwhash_scryptsalsa208sha256(pysodium.crypto_sign_SEEDBYTES+pyspx_slhdsa.shake_128f.crypto_sign_SEEDBYTES, password, self._salt, opslimit=self._ops, memlimit=self._mem) # first 32 bytes Ed25519, next 96 bytes SLH-DSA-SHAKE-128f
      pk1,sk1 = pysodium.crypto_sign_seed_keypair(self._seed[0:pysodium.crypto_sign_SEEDBYTES])
      pk2,sk2 = pyspx_slhdsa.shake_128f.generate_keypair(self._seed[pysodium.crypto_sign_SEEDBYTES:])
      self._pk = SignPublicKey([4,[pk1,pk2]])
      self._sk = SignSecretKey([4,[sk1,sk2]])
      print("  Root Public Key: ", str(self._pk))
    else:
      raise NotImplementedError
    print("")

