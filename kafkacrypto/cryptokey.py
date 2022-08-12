from threading import Lock
import pysodium
import logging
import msgpack
from os import path
from kafkacrypto.utils import msgpack_default_pack
from kafkacrypto.keys import SignPublicKey, KEMPublicKey, KEMSecretKey

class CryptoKey(object):
  """Class utilizing file-backed storage to store (long-term) private key
     material for identity, and memory-backed storage to store (short-term)
     ephemeral private key material.

  Keyword Arguments:
          file (str,file): Filename or File IO object for storing crypto info.
                           Must be readable once.
  """
  #
  # Per instance, defined in init
  #      __file: File object
  #       __spk: signing public key
  #       __ssk: signing private (secret) key
  #        __ek: private key for (un)wrapping opaque bytes
  #  __ephk_legacy: if true, and if version 1 included in __ephk_ver, then send
  #                 new key requests in legacy format (replies to legacy format
  #                 requests are not affected by this setting)
  #  __ephk_ver: ephemeral key exchange key type (KEMPublic/SecretKey version(s))
  # Generated ephemerially, on demand:
  #       __esk: dict of encrypting private (secret) keys (by topic and usage and version)
  #
  def __init__(self, file):
    self._logger = logging.getLogger(__name__)
    if (isinstance(file, (str))):
      if (not path.exists(file)):
        self.__init_cryptokey(file)
      with open(file, 'rb') as f:
        data = f.read()
    else:
      data = file.read()
    datalen = len(data)
    # this should be legacy
    contents = None
    while len(data) and contents is None:
      try:
        contents = msgpack.unpackb(data,raw=True)
      except msgpack.exceptions.ExtraData:
        data = data[:-1]
    if len(data) != datalen:
      self._logger.warning("Cryptokey file had extraneous bytes at end, attempting load anyways.")
    if len(contents) == 2:
      # unversioned legacy format, so update
      self._logger.warning("Cryptokey file is unversioned.")
      contents = [1] + contents + [True,[1]]
      if (isinstance(file, (str))):
        self._logger.warning("Cryptokey file updating from unversioned to versioned format.")
        with open(file, 'wb') as f:
          f.write(msgpack.packb(contents, default=msgpack_default_pack, use_bin_type=True))
    self.__eklock = Lock()
    self.__esk = {}
    if contents[0] == 1:
      # version 1
      self.__ssk = contents[1]
      self.__spk = SignPublicKey(pysodium.crypto_sign_sk_to_pk(self.__ssk))
      self.__ek = contents[2]
      self.__ephk_legacy = contents[3]
      self.__ephk_ver = contents[4]

  def get_spk(self):
    return self.__spk

  def sign_spk(self, msg):
    if self.__spk.version == 1:
      return pysodium.crypto_sign(msg, self.__ssk)
    return None

  def get_epks(self, topic, usage):
    #
    # returns the public key(s) of a new ephemeral encryption key for the specified topic
    # each returned value of the list is to be sent in a single message
    #
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    if (isinstance(usage,(bytes,bytearray))):
      self._logger.debug("passed a usage in bytes (should be string)")
      usage = usage.decode('utf-8')
    with self.__eklock:
      self.__generate_esk(topic, usage)
      rv0 = []
      rv = []
      for v in self.__esk[topic][usage]:
        rv0.append(KEMPublicKey(self.__esk[topic][usage][v]))
      rv.append(rv0)
      if self.__ephk_legacy and 1 in self.__esk[topic][usage]:
        rv.append(KEMPublicKey(self.__esk[topic][usage][1]))
      return rv

  def use_epks(self, topic, usage, pks, clear=True):
    rv = []
    rvp = []
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    if (isinstance(usage,(bytes,bytearray))):
      self._logger.debug("passed a usage in bytes (should be string)")
      usage = usage.decode('utf-8')
    with self.__eklock:
      if not topic in self.__esk or not usage in self.__esk[topic]:
        return (rv,rvp)
      for pk in pks:
        kpk = KEMPublicKey(pk)
        if kpk.get_esk_version() in self.__esk[topic][usage]:
          rv.append(self.__esk[topic][usage][kpk.get_esk_version()].complete_kem(kpk))
          rvp.append(KEMPublicKey(self.__esk[topic][usage][kpk.get_esk_version()]))
      if clear:
        self.__remove_esk(topic, usage)
    return (rv,rvp)

  def wrap_opaque(self, crypto_opaque):
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    return nonce+pysodium.crypto_secretbox(crypto_opaque,nonce,self.__ek)

  def unwrap_opaque(self, crypto_opaque):
    try:
      return pysodium.crypto_secretbox_open(crypto_opaque[pysodium.crypto_secretbox_NONCEBYTES:],crypto_opaque[0:pysodium.crypto_secretbox_NONCEBYTES], self.__ek)
    except:
      return None

  def __generate_esk(self, topic, usage):
    # ephemeral keys are use once only, so always ok to overwrite
    # caller must hold self.__eklock prior to calling
    if not topic in self.__esk:
      self.__esk[topic] = {}
    if not usage in self.__esk[topic]:
      self.__esk[topic][usage] = {}
    for v in self.__ephk_ver:
      self.__esk[topic][usage][v] = KEMSecretKey(v)

  def __remove_esk(self, topic, usage):
    # caller must hold self.__eklock prior to calling
    self.__esk[topic].pop(usage)

  def __init_cryptokey(self, file):
    self._logger.warning("Initializing new CryptoKey file %s", file)
    pk,sk = pysodium.crypto_sign_keypair()
    self._logger.warning("  Public key: %s", pysodium.crypto_sign_sk_to_pk(sk).hex())
    with open(file, "wb") as f:
      f.write(msgpack.packb([1,sk,pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES),True,[1]], default=msgpack_default_pack, use_bin_type=True))
    self._logger.warning("  CryptoKey Initialized. Provisioning required for successful operation.")
