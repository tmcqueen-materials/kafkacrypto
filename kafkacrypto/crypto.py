from threading import Thread
import inspect
from kafkacrypto.utils import format_exception_shim
import pysodium
from time import time,sleep
import msgpack
import logging
from kafkacrypto import TopicPartition,TopicPartitionOffset,OFFSET_BEGINNING
import kafka.serializer
from kafkacrypto.base import KafkaCryptoBase
from kafkacrypto.exceptions import KafkaCryptoError, KafkaCryptoSerializeError
from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.keygenerator import KeyGenerator
from kafkacrypto.utils import log_limited

class KafkaCrypto(KafkaCryptoBase):
  """Class handling the sending and receiving of encrypted messages.

  Keyword Arguments:
              nodeID (str): Node ID
        kp (KafkaProducer): Pre-initialized KafkaProducer, ready for
                            handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values. Always
                            closed on close.
        kc (KafkaConsumer): Pre-initialized KafkaConsumer, ready for
       	       	       	    handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values. Always
                            closed on close.
         config (str,file): Filename or File IO object in which
                            configuration data is stored. Set to None
                            to load from the default location based
                            on nodeID. Must be seekable, with read/
                            write permission, honor sync requests,
                            and not be written by any other program.
                            Only closed if opened by us.
           cryptokey (obj): Optional object implementing the
                            necessary public/private key functions
                            (get/sign_spk,get/use_epk,
                            wrap/unwrap_opaque).
                            Set to None to load from the default
                            location in the configuration file.
                seed (obj): Optional object implementing the
                            necessary ratchet functions
                            (increment, generate). Set to None to
                            load from the default location in
                            the configuration file. Only closed
                            if opened by us.
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
  #               own offsets. This is the next offset to process.
  #               indexed by full topic.
  # _subs_needed: array of root topics for which new subscriptions are needed.
  #   _subs_last: dict of subscriptions that were requested (by root topic).
  #               Each one is itself an array with the timestamp, and an
  #               array of key indices requested.
  #   _cur_pgens: dict of keyidx's for the current producer generator, indexed
  #               by root topic.
  #       _pgens: dict of production encryption key generators, indexed by root
  #               topic, then by 'keyidx', and 'key'/'value'/'secret'.
  #   _new_pgens: Set to true when new pgens were added
  #      _cwaits: dict of statuses on waiting for different key indices indexed by 
  #               root topic and then key index. Used to implement the
  #               wait once logic to ensure no undecryptable messages at
  #               transient key change events.
  #       _cgens: dict of consumption encryption key generators, indexed by root
  #               topic. Each topic has a list of available generators, indexed
  #               by 'keyidx', and finally 'key'/'value'/'secret'.
  #

  def __init__(self, nodeID, kp, kc, config=None, cryptokey=None, seed=None):
    super().__init__(nodeID, kp, kc, config, cryptokey)
    if (seed is None):
      seed = self._cryptostore.load_value('ratchet')
      if seed!=None and seed.startswith('file#'):
        seed = seed[5:]
      if (seed is None):
        seed = self._nodeID + ".seed"
        self._cryptostore.store_value('ratchet', 'file#' + seed)
    self._seed_close = False
    if (isinstance(seed,(str,))):
      self._seed_close = True
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
    self._cwaits = {}
    self._cgens = {}
    self._subs_needed = []
    self._subs_last = {}
    self._last_time = time()

    # Add management frame TPS
    for ntp in [self.MGMT_TOPIC_CHAINS, self.MGMT_TOPIC_ALLOWLIST, self.MGMT_TOPIC_DENYLIST]:
      self._tps[ntp] = TopicPartition(ntp,0)
      self._tps_offsets[ntp] = OFFSET_BEGINNING
      self._tps_updated = True

    kvs = self._cryptostore.load_opaque_value('oldkeys',section="crypto")
    if not (kvs is None):
      kvs = msgpack.unpackb(kvs,raw=True)
      if 'pgens' in kvs.keys() or b'pgens' in kvs.keys():
        self._logger.info("Found pgens to load.")
        t = 'pgens'
        if not (t in kvs.keys()):
          t = b'pgens'
        for [root,ki,ks,b] in kvs[t]:
          if isinstance(root,(bytes,bytearray)):
            self._logger.debug("loaded a pgen root in bytes (should be string)")
            root = root.decode('utf-8')
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

    self._mgmt_thread_stop = False
    self._mgmt_thread = Thread(target=self._process_mgmt_messages,daemon=True)
    self._mgmt_thread.start()

  def close(self):
    self._mgmt_thread_stop = True
    try:
      self._mgmt_thread.join()
    except:
      pass
    finally:
      self._mgmt_thread = None
    try:
      if self._seed_close:
        self._seed.close()
    except:
      pass
    finally:
      self._seed = None
    super().close()

  # Main background processing loop. Must assume that it can "die" at any
  # time, even mid-stride, so ordering of operations to ensure atomicity and
  # durability is critical.
  def _process_mgmt_messages(self):
    while True:
      if self._mgmt_thread_stop:
        break
      # First, process messages
      # we are the only thread ever using _kc, _kp, so we do not need the lock to use them
      msgs = self._kc.poll(timeout_ms=self.MGMT_POLL_INTERVAL, max_records=self.MGMT_POLL_RECORDS)
      # but to actually process messages, we need the lock
      for tp,msgset in msgs.items():
        self._lock.acquire()
        for msg in msgset:
          topic = msg.topic
          if (isinstance(topic,(bytes,bytearray))):
            self._logger.debug("passed a topic in bytes (should be string)")
            topic = topic.decode('utf-8')
          self._tps_offsets[topic] = msg.offset+1
          self._logger.debug("Processing message: %s", msg)
          if topic[-len(self.TOPIC_SUFFIX_REQS):] == self.TOPIC_SUFFIX_REQS:
            root = topic[:-len(self.TOPIC_SUFFIX_REQS)]
            # A new receiver: send all requested keys
            try:
              kreq = msgpack.unpackb(msg.key,raw=True)
              if root in self._pgens.keys():
                ki = []
                s = []
                for ski,sk in self._pgens[root].items():
                  if ski in kreq:
                    ki.append(ski)
                    s.append(sk['secret'])
                if len(ki) > 0:
                  k = msgpack.packb(ki, use_bin_type=True)
                  v = self._cryptoexchange.encrypt_keys(ki, s, root, msgval=msg.value)
                  if not (v is None):
                    self._logger.info("Sending current encryption keys for root=%s to new receiver, msgkey=%s.", root, k)
                    self._kp.send(root + self.TOPIC_SUFFIX_KEYS, key=k, value=v)
                  else:
                    self._logger.info("Failed sending current encryption keys for root=%s to new receiver.", root)
                else:
                  self._logger.info("No keys for root=%s to send to new receiver.", root)
            except Exception as e:
              self._parent._logger.warning("".join(format_exception_shim(e)))
          elif topic[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS:
            root = topic[:-len(self.TOPIC_SUFFIX_KEYS)]
            # New key(s)
            nks = self._cryptoexchange.decrypt_keys(root,msgval=msg.value)
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
                # now that we have this key index, clear from request lists
                if root in self._cwaits.keys():
                  self._cwaits[root].pop(nki, None)
              if root in self._subs_last:
                eki = set(self._subs_last[root][1])
                eki.difference_update(set(nks.keys()))
                if len(eki) > 0:
                  self._logger.warning("For root=%s, the keys %s were requested but not received.", root, eki)
                self._subs_last.pop(root,None)
          elif topic == self.MGMT_TOPIC_CHAINS:
            # New candidate public key chain
            self._logger.info("Received new chain message: %s", msg)
            if msg.key == self._cryptokey.get_spk():
              self._logger.debug("Key matches ours. Validating Chain.")
              newchain = self._cryptoexchange.replace_spk_chain(msg.value)
              if not (newchain is None):
                self._logger.info("New chain is superior, using it.")
                self._cryptostore.store_value('chain',newchain,section='crypto')
          elif topic == self.MGMT_TOPIC_ALLOWLIST:
            self._logger.info("Received new allowlist message: %s", msg)
            allow = self._cryptoexchange.add_allowlist(msg.value)
            if not (allow is None):
              c = pysodium.crypto_hash_sha256(allow)
              self._cryptostore.store_value(c,allow,section='allowlist')
          elif topic == self.MGMT_TOPIC_DENYLIST:
            self._logger.info("Received new denylist message: %s", msg)
            deny = self._cryptoexchange.add_denylist(msg.value)
            if not (deny is None):
              c = pysodium.crypto_hash_sha256(deny)
       	      self._cryptostore.store_value(c,deny,section='denylist')
          else:
            # unknown object
            log_limited(self._logger.warning, "Unknown topic type in message: %s", msg)
        self._lock.release()

      # Flush producer
      try:
        self._kp.flush(timeout=self.MGMT_FLUSH_TIME)
      except Exception as e:
        self._parent._logger.warning("".join(format_exception_shim(e)))

      # Second, deal with subscription changes
      self._lock.acquire()
      self._logger.debug("Processing subscription changes.")
      if self._tps_updated == True:
        self._logger.debug("Subscriptions changed, adjusting.")
        tpo = []
        for tk in self._tps.keys():
          tpo.append(TopicPartitionOffset(self._tps[tk].topic, self._tps[tk].partition, self._tps_offsets[tk]))
        self._kc.assign_and_seek(tpo)
        self._logger.debug("Subscriptions adjusted.")
        if (self._kc.config['group_id'] is None):
          self._logger.info("No group_id, seeking to beginning.")
          self._kc.seek_to_beginning()
        for tk in self._tps.keys():
          if (tk[-len(self.TOPIC_SUFFIX_KEYS):] == self.TOPIC_SUFFIX_KEYS):
            root = tk[:-len(self.TOPIC_SUFFIX_KEYS)]
            if not (root in self._subs_needed):
              self._subs_needed.append(root)
        self._tps_updated = False
      self._lock.release()

      # Third, deal with topics needing subscriptions
      self._lock.acquire()
      self._logger.debug("Process subscriptions.")
      subs_needed_next = []
      for root in self._subs_needed:
        if root in self._cwaits.keys():
          self._logger.debug("Attempting (Re)subscribe to root=%s", root)
          kis = list(self._cwaits[root].keys())
          if len(kis) > 0:
            if (not (root in self._subs_last.keys()) or self._subs_last[root][0]+self.CRYPTO_SUB_INTERVAL<time()):
              k = msgpack.packb(kis, use_bin_type=True)
              v = self._cryptoexchange.signed_epk(root)
              if not (k is None) and not (v is None):
                self._logger.info("Sending new subscribe request for root=%s, msgkey=%s", root, k)
                self._kp.send(root + self.TOPIC_SUFFIX_SUBS, key=k, value=v)
                if self._cryptoexchange.direct_request_spk_chain():
                  # if it may succeed, send directly as well
                  self._kp.send(root + self.TOPIC_SUFFIX_REQS, key=k, value=v)
                self._subs_last[root] = [time(),kis]
              else:
                self._logger.info("Failed to send new subscribe request for root=%s", root)
                subs_needed_next.append(root)
            else:
              self._logger.debug("Deferring (re)subscriptions for root=%s due to pending key request.", root)
              subs_needed_next.append(root)
          else:
            self._logger.debug("No new keys needed for root=%s", root)
      self._subs_needed = subs_needed_next
      self._lock.release()

      # Flush producer
      try:
        self._kp.flush(timeout=self.MGMT_FLUSH_TIME)
      except Exception as e:
        self._parent._logger.warning("".join(format_exception_shim(e)))

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
        self._cryptostore.store_opaque_value('oldkeys',msgpack.packb(kvs, use_bin_type=True),section="crypto")
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
      if (isinstance(topic,(bytes,bytearray))):
        self._parent._logger.debug("passed a topic in bytes (should be string)")
        topic = topic.decode('utf-8')
      if value is None:
        return None
      if (isinstance(value,(KafkaCryptoMessage,))):
        if (value.isCleartext(retry=False)):
          value = value.getMessage(retry=False)
        else:
          # already serialized and encrypted
          return bytes(value)
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
        msg = b'\x01' + msgpack.packb([keyidx,salt,pysodium.crypto_secretbox(value,nonce,key)], use_bin_type=True)
      except Exception as e:
        self._parent._logger.warning("".join(format_exception_shim(e)))
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
      if (isinstance(topic,(bytes,bytearray))):
        self._parent._logger.debug("passed a topic in bytes (should be string)")
        topic = topic.decode('utf-8')
      if bytes_ is None:
        return None
      root = self._parent.get_root(topic)
      if len(bytes_) < 1 or bytes_[0] != 1:
        return KafkaCryptoMessage.fromBytes(bytes_,deser=self,topic=topic)
      try:
        msg = msgpack.unpackb(bytes_[1:],raw=True)
        if (len(msg) != 3):
          raise KafkaCryptoSerializeError("Malformed Message!")
      except Exception as e:
        self._parent._logger.debug("".join(format_exception_shim(e)))
        return KafkaCryptoMessage.fromBytes(bytes_,deser=self,topic=topic)
      ki = msg[0]
      salt = msg[1]
      msg = msg[2]
      self._parent._lock.acquire()
      i = 1
      initial_waiter = False
      try:
        while ((not (root in self._parent._cgens.keys()) or not (ki in self._parent._cgens[root].keys())) and i>0):
          if (not (root in self._parent._cwaits.keys()) or not (ki in self._parent._cwaits[root].keys())):
            self._parent._logger.debug("Setting initial wait for root=%s, key index=%s.", root, ki)
            initial_waiter = True
            # first time we see a topic/key index pair, we wait the initial interval for key exchange
            i = self._parent.DESER_INITIAL_WAIT_INTERVALS
            if not (root in self._parent._cwaits.keys()):
              self._parent._cwaits[root] = {}
            self._parent._cwaits[root][ki] = i
          elif initial_waiter:
            self._parent._cwaits[root][ki] -= 1
          elif (root in self._parent._cwaits.keys()) and (ki in self._parent._cwaits[root].keys()):
            i = self._parent._cwaits[root][ki]
          else:
            i = self.MAX_WAIT_INTERVALS
       	  ntp =	(root+self._parent.TOPIC_SUFFIX_KEYS)
       	  if not (ntp in self._parent._tps):
       	    self._parent._tps[ntp] = TopicPartition(ntp,0)
            self._parent._tps_offsets[ntp] = 0
            self._parent._tps_updated = True
          else:
            if not (root in self._parent._subs_needed):
              self._parent._subs_needed.append(root)
          i=i-1
          if (i > 0):
            self._parent._lock.release()
            sleep(self.WAIT_INTERVAL)
            self._parent._lock.acquire()
        if not (root in self._parent._cgens.keys()) or not (ki in self._parent._cgens[root].keys()):
          self._parent._logger.debug("No decryption key found for root=%s, key index=%s. Returning encrypted message.", root, ki)
          raise ValueError
        gen = self._parent._cgens[root][ki][self._kv]
        key,nonce = gen.generate(salt=salt)
        msg = KafkaCryptoMessage(pysodium.crypto_secretbox_open(msg,nonce,key),ipt=True)
      except:
        return KafkaCryptoMessage.fromBytes(bytes_,deser=self,topic=topic)
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
    if isinstance(root,(bytes,bytearray)):
      self._logger.debug("passed a root in bytes (should be string)")
      root = root.decode('utf-8')
    if (self.MGMT_LONG_KEYINDEX == True):
      ki,ks,kg,vg = self._seed.get_key_value_generators(root, node=self._cryptokey.get_spk())
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
        self._tps[ntp] = TopicPartition(ntp,0)
        self._tps_offsets[ntp] = 0
        self._tps_updated = True
      self._logger.info("Got new producer key for root=%s. New key index=%s", root, ki)

