from threading import Lock
import pysodium
import logging
import msgpack
from os import path
from kafkacrypto.utils import msgpack_default_pack
from kafkacrypto.keys import SignPublicKey, SignSecretKey, KEMPublicKey, KEMSecretKey

class CryptoKey(object):
  """Class utilizing file-backed storage to store (long-term) private key
     material for identity, and memory-backed storage to store (short-term)
     ephemeral private key material.

  Keyword Arguments:
          file (str,file): Filename or File IO object for storing crypto info.
                           Must be readable once.
           keytypes (arr): Optional array of integers specifying the signing
                           keytypes that must be present. If file is a filename,
                           any missing keytypes are generated and added to the
                           file. If file is a File IO object, new keytypes
                           are *not* added if not present, and instead an error
                           is generated.
  """
  #
  # Per instance, defined in init
  #      __file: File object
  #       __spk: list of signing public keys
  #       __ssk: list of signing private (secret) keys
  #        __ek: private key for (un)wrapping opaque bytes
  #  __ephk_legacy: if true, and if version 1 included in __ephk_ver, then send
  #                 new key requests in legacy format (replies to legacy format
  #                 requests are not affected by this setting)
  #  __ephk_ver: ephemeral key exchange key type (KEMPublic/SecretKey version(s))
  # Generated ephemerially, on demand:
  #       __esk: dict of encrypting private (secret) keys (by topic and usage and version)
  #
  def __init__(self, file, keytypes=None):
    self._logger = logging.getLogger(__name__)
    if keytypes is None:
      keytypes = [] # Do not require any specific key types.
    if (isinstance(file, (str))):
      if (not path.exists(file)):
        self.__init_empty_cryptokey(file)
      with open(file, 'rb') as f:
        data = f.read()
    else:
      data = file.read()
    datalen = len(data)
    self.__load_update_cryptokey(data, datalen, file, isinstance(file, (str)), keytypes)

  def __load_update_cryptokey(self, data, datalen, file, isfile, keytypes):
    # this could be legacy
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
      contents = [2] + [[contents[0]]] + [contents[1]] + [True,[1]]
      if (isfile):
        self._logger.warning("Cryptokey file updating from unversioned to version 2 format.")
        with open(file, 'wb') as f:
          f.write(msgpack.packb(contents, default=msgpack_default_pack, use_bin_type=True))
    self.__eklock = Lock()
    self.__esk = {}
    if contents[0] == 1:
      # version 1 (first to support multiple ephemeral key types at once)
      # update to version 2
      contents[0] = 2
      contents[1] = [contents[1]]
      if (isfile):
        self._logger.warning("Cryptokey file updating from version 1 to version 2 format.")
        with open(file, 'wb') as f:
          f.write(msgpack.packb(contents, default=msgpack_default_pack, use_bin_type=True))
    # At this point, contents is version 2 (supports multiple separate signature key types at once)
    self.__ssk_all = []
    self.__spk_all = []
    for ssk in contents[1]:
      nsk = SignSecretKey(ssk)
      self.__ssk_all.append(nsk)
      self.__spk_all.append(SignPublicKey(nsk))
    self.__ek = contents[2]
    self.__ephk_legacy = contents[3]
    self.__ephk_ver = contents[4]
    # make sure all requested keytypes are present (additional ones can also be present)
    keytypes = set(keytypes)
    for spk in self.__spk_all:
      keytypes = keytypes - set([spk.get_type()])
    if len(keytypes) > 0 and not isfile:
      self._logger.error("Cryptokey File IO Object missing requested keytypes = %s", str(keytypes))
      raise ValueError
    for kt in keytypes:
      # generate new keytypes
      nsk = SignSecretKey(kt)
      self.__ssk_all.append(nsk)
      spk = SignPublicKey(nsk)
      self.__spk_all.append(spk)
      contents[1].append(bytes(nsk))
      self._logger.warning("  Adding New Public Key: %s", bytes(spk).hex())
    # Update cryptokey file if new keytypes were created
    if len(keytypes) > 0:
      assert isfile # Should always be true because otherwise we errored out earlier
      self._logger.warning("Cryptokey file updating with new keytypes=%s. Provisioning required for successful operation.", str(keytypes))
      with open(file, 'wb') as f:
        f.write(msgpack.packb(contents, default=msgpack_default_pack, use_bin_type=True))
    # We start with all keytypes enabled; this can be changed by a limit_spk call.
    self.__ssk = self.__ssk_all.copy()
    self.__spk = self.__spk_all.copy()

  def limit_spk(self, keytypes):
    # Limit available spk's to just those keytypes specified (as a list of integers). This does not
    # remove other key types from the file, but does remove them from view of callers (e.g. get_num_spk
    # is reduced, get_id_spk changes, get_spk indexing changes, etc).
    # Usually used once, on startup, to restrict which keytypes are available.
    self.__ssk = []
    self.__spk = []
    for idx in range(0, len(self.__ssk_all)):
      if self.__ssk_all[idx].get_type() in keytypes:
        # Include if not forcing or if it matches a type we are including.
        self.__ssk.append(self.__ssk_all[idx])
        self.__spk.append(self.__spk_all[idx])

  def get_num_spk(self):
    return len(self.__spk)

  def get_id_spk(self):
    rv = b''
    for spk in self.__spk:
      rv += bytes(spk)
    return rv

  def get_spk(self, idx=0):
    return self.__spk[idx]

  def sign_spk(self, msg, idx=0):
    return self.__ssk[idx].crypto_sign(msg)

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

  def __init_empty_cryptokey(self, file):
    self._logger.warning("Initializing new CryptoKey file %s", file)
    with open(file, "wb") as f:
      f.write(msgpack.packb([2,[],pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES),True,[1]], default=msgpack_default_pack, use_bin_type=True))
    self._logger.warning("  CryptoKey Initialized.")
