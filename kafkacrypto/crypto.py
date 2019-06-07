from threading import Thread
import inspect
import traceback
import pysodium
from time import time,sleep
import msgpack
import logging
from kafkacrypto import TopicPartition
import kafka.serializer
from kafkacrypto.base import KafkaCryptoBase
from kafkacrypto.exceptions import KafkaCryptoError, KafkaCryptoSerializeError
from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.keygenerator import KeyGenerator

class KafkaCrypto(KafkaCryptoBase):
  """Class handling the sending and receiving of encrypted messages.

  Keyword Arguments:
              nodeID (str): Node ID
        kp (KafkaProducer): Pre-initialized KafkaProducer, ready for
                            handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
        kc (KafkaConsumer): Pre-initialized KafkaConsumer, ready ofor      
       	       	       	    handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
         config (str,dict): Either a filename in which configuration
                            data is a stored, or a dict of config
                            parameters. Set to None to load from the
                            default location based on nodeID.
       cryptokey (str,obj): Either a filename in which the crypto
                            private key is stored, or an object
                            implementing the necessary functions 
                            (encrypt_keys, decrypt_keys, sign_spk,
                            load/store_crypto_opaque).
                            Set to None to load from the default
                            location based on nodeID.
            seed (str,obj): Either a filename in which the source
                            ratchet seed is stored, or an object
                            implementing the necessary functions
                            (increment, generate). Set to None to
                            load from the default location based
                            on nodeID.
  """

  #
  # Managed by our process, and protected by _lock since they are also
  # utilized by SerDes subclasses:
  # _tps_updated: set to true anytime a non-management process updates
  #               the list of topic-partitions.
  #         _tps: dict of topic-partitions currently listening to. Needed because
  #               KafkaConsumer does not support incremental assignments, so every
  #               change requires (re)subscribing to all TopicPartitions.
  #               indexed by full topic.
  # _tps_offsets: dict of offsets for each tps. Used since kp,kc may have been
  #               configured without groupIDs, so we have to keep track of our
  #               own offsets.
  #               indexed by full topic.
  # _subs_needed: array of root topics for which new subscriptions are needed.
  #   _subs_last: array of times subscriptions were requested (by root topic).
  #   _cur_pgens: dict of keyidx's for the current producer generator, indexed
  #               by root topic.
  #       _pgens: dict of production encryption key generators, indexed by root
  #               topic, then by 'keyidx', and 'key'/'value'/'secret'.
  #   _new_pgens: Set to true when new pgens were added
  #       _cgens: dict of consumption encryption key generators, indexed by root
  #               topic. Each topic has a list of available generators, indexed
  #               by 'keyidx', and finally 'key'/'value'/'secret'.
  #

  def __init__(self, nodeID, kp, kc, config=None, cryptokey=None, seed=None):
    super().__init__(nodeID, kp, kc, config, cryptokey)
    if (seed is None):
      seed = nodeID + ".seed"
    if (isinstance(seed,(str,))):
      seed = Ratchet(file=seed)
    if (not hasattr(seed, 'increment') or not inspect.isroutine(seed.increment) or not hasattr(seed, 'get_key_value_generators') or not inspect.isroutine(seed.get_key_value_generators)):
      raise KafkaCryptoError("Invalid seed source supplied!")

    self._seed = seed
    self._tps_updated = False
    self._tps = {}
    self._tps_offsets = {}
    self._cur_pgens = {}
    self._pgens = {}
    self._new_pgens = False
    self._cgens = {}
    self._subs_needed = []
    self._subs_last = {}
    self._last_time = time()

    kvs = self._cryptokey.load_crypto_opaque()
    if not (kvs is None):
      if 'pgens' in kvs.keys() or b'pgens' in kvs.keys():
        self._logger.info("Found pgens to load.")
        t = 'pgens'
        if not (t in kvs.keys()):
          t = b'pgens'
        for [root,ki,ks,b] in kvs[t]:
          self._logger.info("Attempting load of root=%s, ki=%s, b=%s at %s", root, ki, b, time())
          if time()-b < self.CRYPTO_MAX_PGEN_AGE:
            if not (root in self._pgens.keys()):
              self._pgens[root] = {}
            self._logger.info("Loaded old key keyindex=%s, birth=%s for root=%s", ki, b, root)
            self._pgens[root][ki] = {}
            self._pgens[root][ki]['birth'] = b
            self._pgens[root][ki]['secret'] = ks
            # stored pgens do not have generators as they should never be used for active production
            # (but secret stays around so lost consumers can catch up)

    self._mgmt_thread = Thread(target=self._process_mgmt_messages,daemon=True)
    self._mgmt_thread.start()

  # Main background processing loop. Must assume that it can "die" at any
  # time, even mid-stride, so ordering of operations to ensure atomicity and
  # durability is critical.
  def _process_mgmt_messages(self):
    while True:
      # First, process messages
      # we are the only thread ever using _kc, _kp, so we do not need the lock to use them
      msgs = self._kc.poll(timeout_ms=self.MGMT_POLL_INTERVAL, max_records=self.MGMT_POLL_RECORDS)
      # but to actually process messages, we need the lock
      for tp,msgset in msgs.items():
        self._lock.acquire()
        for msg in msgset:
          topic = msg.topic
          if (isinstance(topic,(str,))):
            topic = topic.encode('utf-8')
          self._tps_offsets[topic] = msg.offset+1
          self._logger.debug("Processing message: %s", msg)
          if topic[-len(self.TOPIC_SUFFIX_REQS):] == self.TOPIC_SUFFIX_REQS:
            root = topic[:-len(self.TOPIC_SUFFIX_REQS)]
            # A new receiver: send all available keys
            if root in self._pgens.keys():
              ki = []
              s = []
              for ski,sk in self._pgens[root].items():
                ki.append(ski)
                s.append(sk['secret'])
              if len(ki) > 0:
                k,v = self._cryptokey.encrypt_keys(ki, s, root, msgkey=msg.key, msgval=msg.value)
                if (not (k is None)) or (not (v is None)):
                  self._logger.info("Sending current encryption keys for root=%s to new receiver, msgkey=%s.", root, msg.key)
                  self._kp.send((root + self.TOPIC_SUFFIX_KEYS).decode('utf-8'), key=k, value=v)
                else:
                  self._logger.info("Failed sending current encryption keys for root=%s to new receiver.", root)
              else:
                self._logger.info("No keys for root=%s to send to new receiver.", root)
          elif topic[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS:
            root = topic[:-len(self.TOPIC_SUFFIX_KEYS)]
            # New key(s)
            nks = self._cryptokey.decrypt_keys(root,msgkey=msg.key,msgval=msg.value)
            if not (nks is None):
              for nki,nk in nks.items():
                self._logger.info("Received new encryption key for root=%s, key index=%s, msgkey=%s", root, nki, msg.key)
                # do not clopper other keys that may exist
                if not (root in self._cgens.keys()):
                  self._cgens[root] = {}
                # but do clobber the same topic,keyID entry
                self._cgens[root][nki] = {}
                self._cgens[root][nki]['key'], self._cgens[root][nki]['value'] = KeyGenerator.get_key_value_generators(nk)
                self._cgens[root][nki]['secret'] = nk
          else:
            # unknown object
            self._logger.warning("Unknown topic type in message: %s", msg)
        self._lock.release()
  
      # Second, deal with subscription changes
      self._lock.acquire()
      self._logger.debug("Processing subscription changes.")
      if self._tps_updated == True:
        self._logger.info("Subscriptions changed, adjusting.")
        self._kc.assign(list(self._tps.values()))
        if (self._kc.config['group_id'] is None):
          self._kc.seek_to_beginning()
        for tk in self._tps.keys():
          if (self._tps_offsets[tk] != 0):
            self._kc.seek(self._tps[tk], self._tps_offsets[tk])
          if (tk[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS):
            root = tk[:-len(self.TOPIC_SUFFIX_KEYS)]
            if not (root in self._subs_needed):
              self._subs_needed.append(root)
        self._tps_updated = False
      self._lock.release()

      # Third, deal with topics needing subscriptions
      self._lock.acquire()
      self._logger.debug("Process subscriptions.")
      for root in self._subs_needed:
        self._logger.info("(Re)subscribing to root=%s", root)
        if not (root in self._subs_last.keys()) or self._subs_last[root]+self.CRYPTO_SUB_INTERVAL<time():
          k,v = self._cryptokey.signed_epk(root)
          if not (k is None) or not (v is None):
            self._subs_last[root] = time()
            self._logger.info("Sending new subscribe request for root=%s, msgkey=%s", root, k)
            self._kp.send((root + self.TOPIC_SUFFIX_SUBS).decode('utf-8'), key=k, value=v)
          else:
            self._logger.info("Failed to send new subscribe request for root=%s", root)
      self._subs_needed = []
      self._lock.release()

      # Fourth, periodically increment ratchet and prune old keys
      self._logger.debug("Checking ratchet time.")
      self._lock.acquire()
      if self._last_time+self.CRYPTO_RATCHET_INTERVAL < time():
        self._logger.info("Periodic ratchet increment.")
        self._last_time = time()
        # prune
        for root,pgens in self._pgens.items():
          rki = []
          for ki,kv in pgens.items():
            if (kv['birth']+self.CRYPTO_MAX_PGEN_AGE<time()):
              rki.append(ki)
          for ki in rki:
            self._pgens[root].pop(ki)
        # increment
        self._cur_pgens = {}
        self._seed.increment()
      self._lock.release()

      # Fifth, write new producer keys if requested
      self._logger.debug("Checking producer keys.")
      self._lock.acquire()
      if self._new_pgens:
        self._logger.info("(Re)writing producer keys.")
        self._new_pgens = False
        kvs = {}
        kvs['pgens'] = []
        for root,pgens in self._pgens.items():
          for ki,kv in pgens.items():
            kvs['pgens'].append([root,ki,kv['secret'],kv['birth']])
            # stored pgens do not have generators as they should never be used for active production
            # (but secret stays around so lost consumers can catch up)
        self._logger.info("Saving %s old production keys.", len(kvs['pgens']))
        self._cryptokey.store_crypto_opaque(kvs)
      self._lock.release()
  
      # Finally, loop back to poll again
  # end of __process_mgmt_messages

  #
  # We have two internal subclasses that implement the Kafka SerDes interface,
  # and handle new keys/subscriptions as needed.
  #
  class Serializer(kafka.serializer.Serializer):
    def __init__(self, parent, kv):
      self._kv = kv
      self._parent = parent

    def serialize(self, topic, value):
      if (isinstance(topic,(str,))):
        topic = topic.encode('utf-8')
      if value is None:
        return None
      if (isinstance(value,(KafkaCryptoMessage,))):
        value = value.getMessage()
      if (not isinstance(value,(bytes,bytearray))):
        raise KafkaCryptoSerializeError("Passed value is not bytes or a KafkaCryptoMessage")
      root = self._parent.get_root(topic)
      self._parent._lock.acquire()
      try:
        #
        # Slow path: if we don't already have a generator for this topic,
        # we have to make one.
        #
        if not (root in self._parent._cur_pgens.keys()):
          self._parent.get_producer(root)
        # Use generator (new or existing)
        keyidx = self._parent._cur_pgens[root]
        pgen = self._parent._pgens[root][keyidx]
        gen = pgen[self._kv]
        salt = gen.salt()
        key,nonce = gen.generate()
        msg = b'\x01' + msgpack.packb([keyidx,salt,pysodium.crypto_secretbox(value,nonce,key)])
      except Exception as e:
        self._parent._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      finally:
        self._parent._lock.release()
      return msg
 
  class Deserializer(kafka.serializer.Deserializer):
    def	__init__(self, parent, kv, max_key_wait_intervals, key_wait_interval):
      self._kv = kv
      self._parent = parent
      self.MAX_WAIT_INTERVALS = max_key_wait_intervals
      self.WAIT_INTERVAL = key_wait_interval

    def deserialize(self, topic, bytes_):
      if (isinstance(topic,(str,))):
        topic = topic.encode('utf-8')
      if bytes_ is None:
        return None
      root = self._parent.get_root(topic)
      if bytes_[0] != 1:
        return KafkaCryptoMessage.fromBytes(bytes_)
      msg = msgpack.unpackb(bytes_[1:])
      if (len(msg) != 3):
        raise KafkaCryptoSerializeError("Malformed Message!")
      ki = msg[0]
      salt = msg[1]
      msg = msg[2]
      self._parent._lock.acquire()
      i = self.MAX_WAIT_INTERVALS+1
      try:
        while ((not (root in self._parent._cgens.keys()) or not (ki in self._parent._cgens[root].keys())) and i>0):
          i = i-1
       	  ntp =	(root+self._parent.TOPIC_SUFFIX_KEYS)
       	  if not (ntp in self._parent._tps):
       	    self._parent._tps[ntp] = TopicPartition(ntp.decode('utf-8'),0)
            self._parent._tps_offsets[ntp] = 0
            self._parent._tps_updated = True
          else:
            if not (root in self._parent._subs_needed):
              self._parent._subs_needed.append(root)
          if (i > 0):
            self._parent._lock.release()
            sleep(self.WAIT_INTERVAL)
            self._parent._lock.acquire()
        if not (root in self._parent._cgens.keys()) or not (ki in self._parent._cgens[root].keys()):
          self._parent._logger.info("No decryption key found for root=%s, key index=%s. Returning encrypted message.", root, ki)
          raise ValueError
        gen = self._parent._cgens[root][ki][self._kv]
        key,nonce = gen.generate(salt=salt)
        msg = KafkaCryptoMessage(pysodium.crypto_secretbox_open(msg,nonce,key),ipt=True)
      except:
        return KafkaCryptoMessage.fromBytes(bytes_)
      finally:
        self._parent._lock.release()
      return msg

  def getKeySerializer(self):
    return self.Serializer(self,'key')
  def getValueSerializer(self):
    return self.Serializer(self,'value')
  def getKeyDeserializer(self, max_key_wait_intervals=0, key_wait_interval=1):
    return self.Deserializer(self,'key',max_key_wait_intervals,key_wait_interval)
  def getValueDeserializer(self, max_key_wait_intervals=0, key_wait_interval=1):
    return self.Deserializer(self,'value',max_key_wait_intervals,key_wait_interval)

  def get_producer(self,root):
    if (self.MGMT_LONG_KEYINDEX == True):
      ki,ks,kg,vg = self._seed.get_key_value_generators(root, node=self._nodeID)
    else:
      ki,ks,kg,vg = self._seed.get_key_value_generators(root)
    self._cur_pgens[root] = ki
    if not (root in self._pgens):
      self._pgens[root] = {}
    if ki in self._pgens[root] and (not ('key' in self._pgens[root][ki].keys()) or not ('value' in self._pgens[root][ki].keys())):
      self._logger.critical("Potential key reuse scenario detected! Incrementing ratchet for safety.")
      self._seed.increment()
    elif not (ki in self._pgens[root].keys()):
      self._new_pgens = True
      self._pgens[root][ki] = {}
      self._pgens[root][ki]['key'] = kg
      self._pgens[root][ki]['value'] = vg
      self._pgens[root][ki]['secret'] = ks
      self._pgens[root][ki]['birth'] = time()
      ntp = (root+self.TOPIC_SUFFIX_REQS)
      if not (ntp in self._tps):
        self._tps[ntp] = TopicPartition(ntp.decode('utf-8'),0)
        self._tps_offsets[ntp] = 0
        self._tps_updated = True
      self._logger.info("Got new producer key for root=%s. New key index=%s", root, ki)

