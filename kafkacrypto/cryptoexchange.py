from threading import Lock
from time import time
from kafkacrypto.utils import format_exception_shim
import pysodium
import msgpack
import logging
from kafkacrypto.chain import process_chain, ProcessChainError, key_in_list
from binascii import unhexlify

class CryptoExchange(object):
  """Class implementing the key exchange protocol used to transmit/receive
     current data encryption keys. 

  Keyword Arguments:
            chain (bytes): Certificate chain for our signing public key.
          cryptokey (obj): Object implementing the necessary public/private 
                           key functions (get/sign_spk,get/use_epk).
             maxage (int): Maximum validity time for sent messages in sec.
                           Optional, default: 86400 (= 1 day)
        randombytes (int): Number of random bytes to add in constructing
                           shared secrets. Optional, minimum default: 32
        allowlist (array): Array of allowlisted public keys. Optional,
                           default: None
         denylist (array): Array of denylisted public keys. Optional,
                           default: None
  """
  #
  # Per instance, defined in init
  #      __maxage: Maximum age (seconds)
  # __randombytes: Random bytes added to exchange
  #   __spk_chain: signing public key chain to root of trust, as array
  #   __cryptokey: Provider of operations involving private keys
  #
  def __init__(self, chain, cryptokey, maxage=0, randombytes=0, allowlist=None, denylist=None):
    self._logger = logging.getLogger(__name__)
    self.__maxage = maxage if (maxage!=None and maxage>0) else 86400
    self.__randombytes = randombytes if randombytes>=32 else 32
    self.__cryptokey = cryptokey
    self.__spk_direct_request = True
    self.__spk_chain = []
    self.__spk_chain_lock = Lock()
    self.__allowdenylist_lock = Lock()
    if not (allowlist is None):
      self.__allowlist = allowlist
    else:
      self.__allowlist = []
    if not (denylist is None):
      self.__denylist = denylist
    else:
      self.__denylist = []
    self.__update_spk_chain(chain)

  def encrypt_keys(self, keyidxs, keys, topic, msgval=None):
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    #
    # msgval should be a msgpacked chain.
    # The public key in the array is the public key to send the key to, using a
    # common DH-derived key between that public key and our private encryption key.
    # Then there is at least one more additional item, random bytes:
    # (3) random bytes
    # Currently items after this are ignored, and reserved for future use.
    #
    try:
      with self.__allowdenylist_lock:
        pk,_ = process_chain(msgval,topic,'key-encrypt-request',allowlist=self.__allowlist,denylist=self.__denylist)
      # Construct shared secret as sha256(topic || random0 || random1 || our_private*their_public)
      epk = self.__cryptokey.get_epk(topic, 'encrypt_keys')
      pks = [pk[2]]
      eks = self.__cryptokey.use_epk(topic, 'encrypt_keys',pks)
      ek = eks[0]
      eks[0] = epk
      random0 = pk[3]
      random1 = pysodium.randombytes(self.__randombytes)
      ss = pysodium.crypto_hash_sha256(topic.encode('utf-8') + random0 + random1 + ek)[0:pysodium.crypto_secretbox_KEYBYTES]
      nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
      # encrypt keys and key indexes (MAC appended, nonce prepended)
      msg = []
      for i in range(0,len(keyidxs)):
        msg.append(keyidxs[i])
        msg.append(keys[i])
      msg = msgpack.packb(msg, use_bin_type=True)
      msg = nonce + pysodium.crypto_secretbox(msg,nonce,ss)
      # this is then put in a msgpack array with the appropriate max_age, poison, and public key(s)
      poison = msgpack.packb([['topics',[topic]],['usages',['key-encrypt']]], use_bin_type=True)
      msg = msgpack.packb([time()+self.__maxage,poison,eks,[random0,random1],msg], use_bin_type=True)
      # and signed with our signing key
      msg = self.__cryptokey.sign_spk(msg)
      # and finally put as last member of a msgpacked array chaining to ROT
      with self.__spk_chain_lock:
        tchain = self.__spk_chain.copy()
        if (len(tchain) == 0):
          poison = msgpack.packb([['topics',[topic]],['usages',['key-encrypt']],['pathlen',1]], use_bin_type=True)
          lastcert = msgpack.packb([time()+self.__maxage,poison,self.__cryptokey.get_spk()], use_bin_type=True)
          _,tempsk = pysodium.crypto_sign_seed_keypair(unhexlify(b'4c194f7de97c67626cc43fbdaf93dffbc4735352b37370072697d44254e1bc6c'))
          tchain.append(pysodium.crypto_sign(lastcert,tempsk))
          provision = msgpack.packb([msgpack.packb([0,b'\x90',self.__cryptokey.get_spk()]),self.__cryptokey.sign_spk(lastcert)], use_bin_type=True)
          self._logger.warning("Current signing chain is empty. Use %s to provision access and then remove temporary root of trust from allowedlist.", provision.hex())
      tchain.append(msg)
      msg = msgpack.packb(tchain, use_bin_type=True)
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return None
    return msg

  def decrypt_keys(self, topic, msgval=None):
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    #
    # msgval should be a msgpacked chain.
    # The public key in the array is a set of public key(s) to combine with our
    # encryption key to get the secret to decrypt the key. If we do not
    # have an encryption key for the topic, we cannot do it until we have one.
    # The next item is then the pair of random values for generating the shared
    # secret, followed by the actual key message.
    #
    try:
      with self.__allowdenylist_lock:
        pk,pkprint = process_chain(msgval,topic,'key-encrypt',allowlist=self.__allowlist,denylist=self.__denylist)
      if (len(pk) < 5):
        if not (pkprint is None):
          raise ProcessChainError("Unexpected number of chain elements:", pkprint)
        else:
          raise ValueError("Unexpected number of chain elements!")
      random0 = pk[3][0]
      random1 = pk[3][1]
      nonce = pk[4][0:pysodium.crypto_secretbox_NONCEBYTES]
      msg = pk[4][pysodium.crypto_secretbox_NONCEBYTES:]
      eks = self.__cryptokey.use_epk(topic, 'decrypt_keys', pk[2], clear=False)
      for ck in eks:
        # Construct candidate shared secrets as sha256(topic || random0 || random1 || our_private*their_public)
        ss = pysodium.crypto_hash_sha256(topic.encode('utf-8') + random0 + random1 + ck)[0:pysodium.crypto_secretbox_KEYBYTES]
        # decrypt and return key
        try:
          msg = msgpack.unpackb(pysodium.crypto_secretbox_open(msg,nonce,ss),raw=True)
          rvs = {}
          for i in range(0,len(msg),2):
            rvs[msg[i]] = msg[i+1]
          if len(rvs) < 1 or 2*len(rvs) != len(msg):
            raise ValueError
        except:
          pass
        else:
          # clear the esk/epk we just used
          self.__cryptokey.use_epk(topic, 'decrypt_keys', [])
          return rvs
      raise ValueError
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      pass
    return None

  def signed_epk(self, topic, epk=None):
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("passed a topic in bytes (should be string)")
      topic = topic.decode('utf-8')
    #
    # returns the public key of a current or given ephemeral key for the specified topic
    # (generating a new one if not present), signed by our signing key,
    # with a fresh random value, and with the chain to the ROT prepended.
    #
    try:
      if epk is None:
        epk = self.__cryptokey.get_epk(topic,'decrypt_keys')
      random0 = pysodium.randombytes(self.__randombytes)
      # we allow either direct-to-producer or via-controller key establishment
      poison = msgpack.packb([['topics',[topic]],['usages',['key-encrypt-request','key-encrypt-subscribe']]], use_bin_type=True)
      msg = msgpack.packb([time()+self.__maxage,poison,epk,random0], use_bin_type=True)
      # and signed with our signing key
      msg = self.__cryptokey.sign_spk(msg)
      # and finally put as last member of a msgpacked array chaining to ROT
      with self.__spk_chain_lock:
        tchain = self.__spk_chain.copy()
        if (len(tchain) == 0):
          # Use default for direct use when empty.
          self.__spk_direct_request = True
          poison = msgpack.packb([['topics',[topic]],['usages',['key-encrypt-request','key-encrypt-subscribe']],['pathlen',1]], use_bin_type=True)
          lastcert = msgpack.packb([time()+self.__maxage,poison,self.__cryptokey.get_spk()], use_bin_type=True)
       	  _,tempsk = pysodium.crypto_sign_seed_keypair(unhexlify(b'4c194f7de97c67626cc43fbdaf93dffbc4735352b37370072697d44254e1bc6c'))
          tchain.append(pysodium.crypto_sign(lastcert,tempsk))
       	  provision = msgpack.packb([msgpack.packb([0,b'\x90',self.__cryptokey.get_spk()]),self.__cryptokey.sign_spk(lastcert)], use_bin_type=True)
          self._logger.warning("Current signing chain is empty. Use %s to provision access and then remove temporary root of trust from allowedlist.", provision.hex())
      tchain.append(msg)
      msg = msgpack.packb(tchain, use_bin_type=True)
      return msg
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      pass
    return None

  def add_allowlist(self, allow):
    self.__allowdenylist_lock.acquire()
    try:
      pk,_ = process_chain(allow,None,'key-allowlist',allowlist=self.__allowlist,denylist=self.__denylist)
      if (len(pk) >= 4):
        apk = msgpack.unpackb(pk[3],raw=True)
        if pk[2] != apk[2]:
          self._logger.info("Mismatch in keys for allowlist %s vs %s.",pk[2].hex(),apk[2].hex())
          raise ValueError("Mismatch in keys for allowlist.")
        if key_in_list(pk[3],self.__allowlist)==None:
          self.__allowlist.append(pk[3])
        else:
          self._logger.info("Key %s already in allowlist",pk[2].hex())
          raise ValueError("Key already in allowlist!")
        self._logger.warning("Added key %s to allowlist",pk[2].hex())
        return pk[3]
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return None
    finally:
      self.__allowdenylist_lock.release()

  def add_denylist(self, deny):
    self.__allowdenylist_lock.acquire()
    try:
      pk,_ = process_chain(deny,None,'key-denylist',allowlist=self.__allowlist,denylist=self.__denylist)
      if (len(pk) >= 4):
        apk = msgpack.unpackb(pk[3],raw=True)
        if pk[2] != apk[2]:
          self._logger.info("Mismatch in keys for denylist %s vs %s.",pk[2].hex(),apk[2].hex())
          raise ValueError("Mismatch in keys for denylist.")
        if key_in_list(pk[3],self.__denylist)==None:
          self.__denylist.append(pk[3])
        else:
          self._logger.info("Key %s already in denylist",pk[2].hex())
          raise ValueError("Key already in denylist!")
        self._logger.warning("Added key %s to denylist",pk[2].hex())
       	return pk[3]
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return None
    finally:
      self.__allowdenylist_lock.release()

  def direct_request_spk_chain(self):
    with self.__spk_chain_lock:
      rv = self.__spk_direct_request
    return rv

  def replace_spk_chain(self, newchain):
    # update_spk_chain captures any exceptions and returns None when they happen.
    newchain = self.__update_spk_chain(newchain)
    return newchain

  def __update_spk_chain(self, newchain):
    #
    # We have a new candidate chain to replace the current one (if any). We
    # first must check it is a valid chain ending in our signing public key.
    #
    if (newchain is None):
      return None
    try:
      with self.__allowdenylist_lock:
        pk,pkprint = process_chain(newchain,None,None,allowlist=self.__allowlist,denylist=self.__denylist)
      if (len(pk) < 3 or pk[2] != self.__cryptokey.get_spk()):
        if not (pkprint is None):
          raise ProcessChainError("New chain does not match current signing publickey:", pkprint)
        else:
          raise ValueError("New chain does not match current signing public key,")
      # If we get here, it is a valid chain. So now we need
      # to see if it is "superior" than our current chain.
      # This means a larger minimum max_age.
      min_max_age = 0
      with self.__spk_chain_lock:
        for cpk in self.__spk_chain:
          if (min_max_age == 0 or cpk[0]<min_max_age):
            min_max_age = cpk[0]
      if (pk[0] < min_max_age):
        raise ProcessChainError("New chain has shorter expiry time than current chain.", pkprint)
      with self.__spk_chain_lock:
        self.__spk_chain = msgpack.unpackb(newchain,raw=True)
        self._logger.warning("Utilizing new chain: %s", str(pkprint))
      # Check if we are capable of direct key requests (default is "no")
      with self.__spk_chain_lock:
        self.__spk_direct_request = False
        self._logger.debug("Defaulting new chain to not handle direct requests.")
      try:
        with self.__allowdenylist_lock:
          pk,_ = process_chain(newchain,None,'key-encrypt-request',allowlist=self.__allowlist,denylist=self.__denylist)
        if len(pk) >= 3:
          with self.__spk_chain_lock:
            self._logger.info("  New chain supports direct key requests. Enabling.")
            self.__spk_direct_request = True
      except Exception as e:
        # exceptions when checking direct mean it is not supported
        with self.__spk_chain_lock:
          self._logger.info("  New chain does not support direct key requests. Disabling.")
          self.__spk_direct_request = False
      return newchain
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return None
