from time import time
import traceback
import pysodium
import msgpack
import logging
from kafkacrypto.chain import process_chain

class CryptoExchange(object):
  """Class implementing the key exchange protocol used to transmit/receive
     current data encryption keys. 

  Keyword Arguments:
              rot (bytes): Root of trust for received messages.
         chainrot (bytes): Root of trust for sent messages.
            chain (bytes): Certificate chain for our signing public key.
          cryptokey (obj): Object implementing the necessary public/private 
                           key functions (get/sign_spk,get/use_epk).
             maxage (int): Maximum validity time for sent messages in sec.
                           Optional, default: 86400 (= 1 day)
        randombytes (int): Number of random bytes to add in constructing
                           shared secrets. Optional, minimum default: 32
         denylist (array): Array of denylisted public keys. Optional,
                           default: None
  """
  #
  # Per instance, defined in init
  #         __rot: Root of Trust for received messages
  #    __chainrot: Root of Trust for our trust chain
  #      __maxage: Maximum age (seconds)
  # __randombytes: Random bytes added to exchange
  #   __spk_chain: signing public key chain to root of trust, as array
  #   __cryptokey: Provider of operations involving private keys
  #
  def __init__(self, rot, chainrot, chain, cryptokey, maxage=0, randombytes=0, denylist=None):
    self._logger = logging.getLogger(__name__)
    self.__maxage = maxage if maxage>0 else 86400
    self.__randombytes = randombytes if randombytes>=32 else 32
    self.__cryptokey = cryptokey
    self.__rot = rot
    self.__chainrot = chainrot
    self.__spk_chain = []
    self.__denylist = denylist
    self.__update_spk_chain(chain)

  def encrypt_keys(self, keyidxs, keys, topic, msgkey=None, msgval=None):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    #
    # msgval should be a msgpacked chain.
    # The public key in the array is the public key to send the key to, using a
    # common DH-derived key between that public key and our private encryption key.
    # Then there is at least one more additional item, random bytes:
    # (3) random bytes
    # There then might be additional public keys:
    # (4) public key
    # ...
    # Which, if present, are multiplied by our secret key and returned along
    # with our public key in the response. This is only safe because:
    #  1. A fresh ephemeral secret key is used for each call of encrypt_keys
    #  2. We validate that the additional public keys are not equal to the
    #     one used to derive the shared secret for this call
    # Together, these ensure that an attacker cannot use the additional public
    # keys feature to learn the common DH shared secret for another session.
    #
    try:
      pk = process_chain(topic,self.__rot,msgval,b'key-encrypt-request',denylist=self.__denylist)
      # Construct shared secret as sha256(topic || random0 || random1 || our_private*their_public)
      epk = self.__cryptokey.get_epk(topic)
      pks = [pk[2]]
      for extrapk in pk[4:]:
        if (extrapk != pk[2]):
          pks.append(extrapk)
      eks = self.__cryptokey.use_epk(topic, pks)
      ek = eks[0]
      eks[0] = epk
      random0 = pk[3]
      random1 = pysodium.randombytes(self.__randombytes)
      ss = pysodium.crypto_hash_sha256(topic + random0 + random1 + ek)[0:pysodium.crypto_secretbox_KEYBYTES]
      nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
      # encrypt keys and key indexes (MAC appended, nonce prepended)
      msg = []
      for i in range(0,len(keyidxs)):
        msg.append(keyidxs[i])
        msg.append(keys[i])
      msg = msgpack.packb(msg)
      msg = nonce + pysodium.crypto_secretbox(msg,nonce,ss)
      # this is then put in a msgpack array with the appropriate max_age, poison, and public key(s)
      poison = msgpack.packb([[b'topics',[topic]],[b'usages',[b'key-encrypt']]])
      msg = msgpack.packb([time()+self.__maxage,poison,eks,[random0,random1],msg])
      # and signed with our signing key
      msg = self.__cryptokey.sign_spk(msg)
      # and finally put as last member of a msgpacked array chaining to ROT
      tchain = self.__spk_chain.copy()
      tchain.append(msg)
      msg = msgpack.packb(tchain)
    except Exception as e:
      self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return (None, None)
    return (msgkey, msg)

  def decrypt_keys(self, topic, msgkey=None, msgval=None):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    #
    # msgval should be a msgpacked chain.
    # The public key in the array is a set of public key(s) to combine with our
    # encryption key to get the secret to decrypt the key. If we do not
    # have an encryption key for the topic, we cannot do it until we have one.
    # The next item is then the pair of random values for generating the shared
    # secret, followed by the actual key message.
    #
    try:
      pk = process_chain(topic,self.__rot,msgval,b'key-encrypt',denylist=self.__denylist)
      if (len(pk) < 5):
        raise ValueError
      random0 = pk[3][0]
      random1 = pk[3][1]
      nonce = pk[4][0:pysodium.crypto_secretbox_NONCEBYTES]
      msg = pk[4][pysodium.crypto_secretbox_NONCEBYTES:]
      eks = self.__cryptokey.use_epk(topic, pk[2], clear=False)
      for ck in eks:
        # Construct candidate shared secrets as sha256(topic || random0 || random1 || our_private*their_public)
        ss = pysodium.crypto_hash_sha256(topic + random0 + random1 + ck)[0:pysodium.crypto_secretbox_KEYBYTES]
        # decrypt and return key
        try:
          msg = msgpack.unpackb(pysodium.crypto_secretbox_open(msg,nonce,ss))
          rvs = {}
          for i in range(0,len(msg),2):
            rvs[msg[i]] = msg[i+1]
          if len(rvs) < 1 or 2*len(rvs) != len(msg):
            raise ValueError
        except:
          pass
        else:
          self.__cryptokey.use_epk(topic, [])
          return rvs
      raise ValueError
    except Exception as e:
      self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      pass
    return None

  def signed_epk(self, topic, epk=None):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    #
    # returns the public key of a current or given ephemeral key for the specified topic
    # (generating a new one if not present), signed by our signing key,
    # with a fresh random value, and with the chain to the ROT prepended.
    #
    try:
      if epk is None:
        epk = self.__cryptokey.get_epk(topic)
      random0 = pysodium.randombytes(self.__randombytes)
      # we allow either direct-to-producer or via-controller key establishment
      poison = msgpack.packb([[b'topics',[topic]],[b'usages',[b'key-encrypt-request',b'key-encrypt-subscribe']]])
      msg = msgpack.packb([time()+self.__maxage,poison,epk,random0])
      # and signed with our signing key
      msg = self.__cryptokey.sign_spk(msg)
      # and finally put as last member of a msgpacked array chaining to ROT
      tchain = self.__spk_chain.copy()
      tchain.append(msg)
      msg = msgpack.packb(tchain)
      return (self.__cryptokey.get_spk(), msg)
    except Exception as e:
      self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      pass
    return (None, None)

  def replace_spk_chain(self, newchain):
    try:
      self.__update_spk_chain(newchain)
      return newchain
    except ValueError:
      return None

  def __update_spk_chain(self, newchain):
    #
    # We have a new candidate chain to replace the current one (if any). We
    # first must check it is a valid chain ending in our signing public key.
    #
    try:
      pk = process_chain(b'',self.__chainrot,newchain,b'',denylist=self.__denylist)
      if (len(pk) < 3 or pk[2] != self.__cryptokey.get_spk()):
        raise ValueError("New chain does not match current signing public key,")
      # If we get here, it is a valid chain. So now we need
      # to see if it is "superior" than our current chain.
      # This means a larger minimum max_age.
      min_max_age = 0
      for cpk in self.__spk_chain:
        if (min_max_age == 0 or cpk[0]<min_max_age):
          min_max_age = cpk[0]
      if (pk[0] < min_max_age):
        raise ValueError("New chain has shorter expiry time than current chain.")
      self.__spk_chain = msgpack.unpackb(newchain)
      return newchain
    except Exception as e:
      self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return None
