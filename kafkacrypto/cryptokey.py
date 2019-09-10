import pysodium
import logging
import msgpack

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
  #       __epk: dict of encrypting public keys (by topic)
  #       __esk: dict of encrypting private (secret) keys (by topic)
  #
  def __init__(self, file):
    self._logger = logging.getLogger(__name__)
    if (isinstance(file, (str))):
      with open(file, 'rb') as file:
        data = file.read()
    else:
      data = file.read()
    datalen = len(data)
    # this should be legacy
    contents = None
    while len(data) and contents is None:
      try:
        contents = msgpack.unpackb(data)
      except msgpack.exceptions.ExtraData:
        data = data[:-1]
    if len(data) != datalen:
      self._logger.warning("Cryptokey file had extraneous bytes at end, attempting load anyways.")
    self.__esk = {}
    self.__epk = {}
    self.__ssk = contents[0]
    self.__spk = pysodium.crypto_sign_sk_to_pk(self.__ssk)
    self.__ek = contents[1]

  def get_spk(self):
    return self.__spk

  def sign_spk(self, msg):
    return pysodium.crypto_sign(msg, self.__ssk)

  def get_epk(self, topic):
    #
    # returns the public key of a new ephemeral encryption key for the specified topic
    #
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    self.__generate_esk(topic)
    return self.__epk[topic]

  def use_epk(self, topic, pks, clear=True):
    rv = []
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    if not topic in self.__esk:
      return rv
    for pk in pks:
      rv.append(pysodium.crypto_scalarmult_curve25519(self.__esk[topic],pk))
    if clear:
      self.__remove_esk(topic)
    return rv

  def wrap_opaque(self, crypto_opaque):
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
    return nonce+pysodium.crypto_secretbox(crypto_opaque,nonce,self.__ek)

  def unwrap_opaque(self, crypto_opaque):
    try:
      return pysodium.crypto_secretbox_open(crypto_opaque[pysodium.crypto_secretbox_NONCEBYTES:],crypto_opaque[0:pysodium.crypto_secretbox_NONCEBYTES], self.__ek)
    except:
      return None

  def __generate_esk(self, topic):
    # ephemeral keys are use once only, so always ok to overwrite
    self.__esk[topic] = pysodium.randombytes(pysodium.crypto_scalarmult_curve25519_BYTES)
    self.__epk[topic] = pysodium.crypto_scalarmult_curve25519_base(self.__esk[topic])

  def __remove_esk(self, topic):
    self.__esk.pop(topic)
    self.__epk.pop(topic)
