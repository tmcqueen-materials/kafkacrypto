from threading import Thread
import inspect
import pysodium
import time
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
                            (encrypt_key, decrypt_key, sign_spk).
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
  #   _receivers: dict of encryption key receivers, indexed by root topic,
  #               each also a dict with (key = msgkey, value = msgval).
  #   _new_pgens: holding dict of encryption key generators that need to
  #               be sent off; each one is a dict of four items (topic,
  #               keyidx, key, value).
  #       _pgens: dict of production encryption key generators, indexed by root
  #               topic, then by 'keyidx', 'key' and 'value'.
  #       _cgens: dict of consumption encryption key generators, indexed by root
  #               topic. Each topic has a list of available generators, indexed
  #               by keyID, and finally 'key' and 'value'.
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
    self._new_pgens = {}
    self._pgens = {}
    self._cgens = {}
    self._receivers = {}
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
            # A new receiver: send current key
            if not (root in self._receivers.keys()):
              self._receivers[root] = {}
            self._receivers[root][msg.key] = msg.value
            if root in self._pgens.keys():
              si = self._pgens[root]['keyidx']
              s = self._pgens[root]['key'].secret()
              if (s != self._pgens[root]['value'].secret()):
                s = s + self._pgens[root]['value'].secret()
              k,v = self._cryptokey.encrypt_key(si, s, root, msgkey=msg.key, msgval=msg.value)
              if (not (k is None)) or (not (v is None)):
                self._logger.info("Sending current encryption keys for root=%s to new receiver, msgkey=%s.", root, msg.key)
                self._kp.send((root + self.TOPIC_SUFFIX_KEYS).decode('utf-8'), key=k, value=v)
              else:
                self._logger.info("Failed sending current encryption keys for root=%s to new receiver.", root)
          elif topic[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS:
            root = topic[:-len(self.TOPIC_SUFFIX_KEYS)]
            # A new key
            nki,nk = self._cryptokey.decrypt_key(root,msgkey=msg.key,msgval=msg.value)
            if not (nk is None):
              self._logger.info("Received new encryption key for root=%s, key index=%s, msgkey=%s", root, nki, msg.key)
              # do not clopper other keys that may exist
              if not (root in self._cgens.keys()):
                self._cgens[root] = {}
              # but do clobber the same topic,keyID entry
              self._cgens[root][nki] = {}
              self._cgens[root][nki]['key'] = KeyGenerator.key_generator(nk)
              self._cgens[root][nki]['value'] = KeyGenerator.value_generator(nk)
          else:
            # unknown object
            self._logger.warning("Unknown topic type in message: %s", msg)
        self._lock.release()
  
      # Second, walk through _new_pgens and send accordingly
      self._lock.acquire()
      for pidx in self._new_pgens.keys():
        root = self._new_pgens[pidx]['topic']
        ki = self._new_pgens[pidx]['keyidx']
        kg = self._new_pgens[pidx]['key']
        vg = self._new_pgens[pidx]['value']
        s = kg.secret()
        si = ki
        if (s != vg.secret()):
          s = s + vg.secret()
        if root in self._receivers.keys():
          todel = []
          for msgkey in self._receivers[root].keys():
            k,v = self._cryptokey.encrypt_key(si, s, root, msgkey=msgkey, msgval=self._receivers[root][msgkey])
            if (not (k is None)) or (not (v is None)):
              self._kp.send((root + self.TOPIC_SUFFIX_KEYS).decode('utf-8'), key=k, value=v)
              self._logger.info("Sending new encryption keys for root=%s to current receiver msgkey=%s.", root, msgkey)
            else:
              todel.append(msgkey)
              self._logger.info("Could not send encryption keys for root=%s to current receiver, msgkey=%s, deleting receiver.", root, msgkey)
          for msgkey in todel:
            self._receivers[root].pop(msgkey)
      self._new_pgens = {}
      self._lock.release()
  
      # Third, Deal with subscription changes
      self._lock.acquire()
      if self._tps_updated == True:
        self._kc.assign(list(self._tps.values()))
        self._kc.seek_to_beginning()
        for tk in self._tps.keys():
          if (self._tps_offsets[tk] != 0):
            self._kc.seek(self._tps[tk], self._tps_offsets[tk])
          if (tk[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS):
            root = tk[:-len(self.TOPIC_SUFFIX_KEYS)]
            k,v = self._cryptokey.signed_epk(root)
            if not (k is None) or not (v is None):
              self._logger.info("Sending new subscribe request for root=%s, msgkey=%s", root, k)
              self._kp.send((root + self.TOPIC_SUFFIX_SUBS).decode('utf-8'), key=k, value=v)
        self._tps_updated = False
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
        if not (root in self._parent._pgens.keys()):
          self._parent.refreshProducer(topic)
        # Use generator (new or existing)
        pgen = self._parent._pgens[root]
        keyidx = pgen['keyidx']
        gen = pgen[self._kv]
        salt = gen.salt()
        key,nonce = gen.generate(salt=salt) 
        msg = b'\x01' + msgpack.packb([keyidx,salt,pysodium.crypto_secretbox(value,nonce,key)])
      except Exception as e:
        self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
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
          if (i > 0):
            self._parent._lock.release()
            time.sleep(self.WAIT_INTERVAL)
            self._parent._lock.acquire()
        if not (root in self._parent._cgens.keys()) or not (ki in self._parent._cgens[root].keys()):
          self._logger.info("No decryption key found for root=%s, key index=%s. Returning encrypted message.", root, ki)
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

  def refreshProducer(self,topic):
    if (isinstance(topic,(str,))):
      topic = topic.encode('utf-8')
    root = self.get_root(topic)
    ki,kg,vg = self._seed.get_key_value_generators(root)
    if (self.MGMT_LONG_KEYINDEX == True):
      if (isinstance(ki, (int,))):
        ki = ki.to_bytes(16, byteorder='big')
      elif (isinstance(ki, (str,))):
        ki = ki.encode('utf-8')
      elif (isinstance(ki, (bytes, bytearray))):
        pass
      else:
        ki = bytes(ki)
      ki = pysodium.crypto_generichash(self._nodeID_bytes + ki)
    self._pgens[root] = {}
    self._pgens[root]['keyidx'] = ki
    self._pgens[root]['key'] = kg
    self._pgens[root]['value'] = vg
    self._new_pgens[root + bytes(ki)] = {'topic':root, 'keyidx': ki, 'key': kg, 'value': vg}
    ntp = (root+self.TOPIC_SUFFIX_REQS)
    if not (ntp in self._tps):
      self._tps[ntp] = TopicPartition(ntp.decode('utf-8'),0)
      self._tps_offsets[ntp] = 0
      self._tps_updated = True
    self._logger.info("Refreshed producer key for topic=%s, root=%s. New key index=%s", topic, root, ki)
    return self._pgens[root]
