from threading import Lock
import pysodium
import logging
import msgpack
from os import path

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
  # Generated ephemerially, on demand:
  #       __epk: dict of encrypting public keys (by topic and usage)
  #       __esk: dict of encrypting private (secret) keys (by topic and usage)
  #
  def __init__(self, file):
    self._logger = logging.getLogger(__name__)
    if (isinstance(file, (str))):
      if (not path.exists(file)):
        self.__init_cryptokey(file)
      with open(file, 'rb') as file:
        data = file.read()
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
    self.__eklock = Lock()
    self.__esk = {}
    self.__epk = {}
    self.__ssk = contents[0]
    self.__spk = pysodium.crypto_sign_sk_to_pk(self.__ssk)
    self.__ek = contents[1]

  def get_spk(self):
    return self.__spk

  def sign_spk(self, msg):
    return pysodium.crypto_sign(msg, self.__ssk)

  def get_epk(self, topic, usage):
    #
    # returns the public key of a new ephemeral encryption key for the specified topic
    #
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    if (isinstance(usage,(bytes,bytearray))):
      self._logger.debug("passed a usage in bytes (should be string)")
      usage = usage.decode('utf-8')
    with self.__eklock:
      self.__generate_esk(topic, usage)
      return self.__epk[topic][usage]

  def use_epk(self, topic, usage, pks, clear=True):
    rv = []
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    if (isinstance(usage,(bytes,bytearray))):
      self._logger.debug("passed a usage in bytes (should be string)")
      usage = usage.decode('utf-8')
    with self.__eklock:
      if not topic in self.__esk or not usage in self.__esk[topic]:
        return rv
      for pk in pks:
        rv.append(pysodium.crypto_scalarmult_curve25519(self.__esk[topic][usage],pk))
      if clear:
        self.__remove_esk(topic, usage)
    return rv

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
    if not topic in self.__esk or not topic in self.__epk:
      self.__esk[topic] = {}
      self.__epk[topic] = {}
    self.__esk[topic][usage] = pysodium.randombytes(pysodium.crypto_scalarmult_curve25519_BYTES)
    self.__epk[topic][usage] = pysodium.crypto_scalarmult_curve25519_base(self.__esk[topic][usage])

  def __remove_esk(self, topic, usage):
    # caller must hold self.__eklock prior to calling
    self.__esk[topic].pop(usage)
    self.__epk[topic].pop(usage)

  def __init_cryptokey(self, file):
    self._logger.warning("Initializing new CryptoKey file %s", file)
    pk,sk = pysodium.crypto_sign_keypair()
    self._logger.warning("  Public key: %s", pysodium.crypto_sign_sk_to_pk(sk).hex())
    with open(file, "wb") as f:
      f.write(msgpack.packb([sk,pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)], use_bin_type=True))
    self._logger.warning("  CryptoKey Initialized. Provisioning required for successful operation.")
