from threading import Thread
import inspect
import pysodium
from time import time
import msgpack
from kafkacrypto import TopicPartition
from kafkacrypto.base import KafkaCryptoBase
from kafkacrypto.exceptions import KafkaCryptoControllerError
from kafkacrypto.provisioners import Provisioners

class KafkaCryptoController(KafkaCryptoBase):
  """ A simple controller implementation, resigning requests for keys
      for a particular resource, using our key (signed by ROT), if
      request is signed by a known provisioner. To function properly,
      and not miss messages, the provided KafkaConsumer must be 
      configured so that client_id and group_id are both set to nodeID,
      and that enable_auto_commit (automatic committing) is False.

  Keyword Arguments:
              nodeID (str): Node ID
        kp (KafkaProducer): Pre-initialized KafkaProducer, ready for
                            handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
        kc (KafkaConsumer): Pre-initialized KafkaConsumer, ready for      
       	       	       	    handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
         config (str,file): Filename or File IO object in which
                            configuration data is stored. Set to None
                            to load from the default location based
                            on nodeID. Must be seekable, with read/
                            write permission, honor sync requests,
                            and not be written by any other program.
           cryptokey (obj): Optional object implementing the
                            necessary public/private key functions
                            (get/sign_spk,get/use_epk,
                            wrap/unwrap_opaque).
                            Set to None to load from the default
                            location in the configuration file.
        provisioners (obj): Optional object implementing the
                            necessary allowed provisioner functions
                            (reencrypt_request). Set to None to
                            load from the default location in
                            the configuration file.
  """

  def __init__(self, nodeID, kp, kc, config=None, cryptokey=None, provisioners=None):
    super().__init__(nodeID, kp, kc, config, cryptokey)
    if (not ('enable_auto_commit' in self._kc.config) or self._kc.config['enable_auto_commit'] != False):
      self._logger.warning("Auto commit not disabled, controller may miss messages.")
    if (self._kc.config['group_id'] is None):
      self._logger.warning("Group ID not set, controller may miss messages.")
    if (provisioners is None):
      denylist = self._cryptostore.load_section('denylist')
      if not (denylist is None):
        denylist = denylist.values()
      provisioners = self._cryptostore.load_section('provisioners')
      if provisioners!=None:
        provisioners = provisioners.values()
      else:
        # attempt legacy load
        with open(nodeID + ".provisioners", "rb") as provs:
          provisioners = msgpack.unpackb(provs.read())
        i = 0
        while i < len(provisioners):
          self._cryptostore.store_value('provisioners'+str(i),provisioners[i],section='provisioners')
          i += 1
      provisioners = Provisioners(provisioners, denylist=denylist)
    if (not hasattr(provisioners, 'reencrypt_request') or not inspect.isroutine(provisioners.reencrypt_request)):
      raise KafkaCryptoControllerError("Invalid provisioners source supplied!")

    self._provisioners = provisioners
    self._last_subscribed_time = 0
    self._mgmt_thread = Thread(target=self._process_mgmt_messages,daemon=True)
    self._mgmt_thread.start()

  # Main background processing loop. Must assume that it can "die" at any
  # time, even mid-stride, so ordering of operations to ensure atomicity and
  # durability is critical.
  def _process_mgmt_messages(self):
    while True:
      # First, (Re)subscribe if needed
      if ((time()-self._last_subscribed_time) >= self.MGMT_SUBSCRIBE_INTERVAL):
        self._logger.debug("Initiating resubscribe...")
        trx = "(.*\\" + self.TOPIC_SUFFIX_SUBS.decode('utf-8') + "$)"
        self._kc.subscribe(pattern=trx)
        self._last_subscribed_time = time()
        self._logger.info("Resubscribed to topics.")

      # Second, process messages
      # we are the only thread ever using _kc, _kp, so we do not need the lock to use them
      self._logger.debug("Initiating poll...")
      msgs = self._kc.poll(timeout_ms=self.MGMT_POLL_INTERVAL, max_records=self.MGMT_POLL_RECORDS)
      self._logger.debug("Poll complete with %i msgsets.", len(msgs))
      # but to actually process messages, we need the lock
      for tp,msgset in msgs.items():
        self._logger.debug("Topic %s Partition %i has %i messages", tp.topic, tp.partition, len(msgset))
        self._lock.acquire()
        for msg in msgset:
          self._logger.debug("Processing message: %s", msg)
          topic = msg.topic
          if (isinstance(topic,(str,))):
            topic = topic.encode('utf-8')
          if topic[-len(self.TOPIC_SUFFIX_SUBS):] == self.TOPIC_SUFFIX_SUBS:
            root = topic[:-len(self.TOPIC_SUFFIX_SUBS)]
       	    self._logger.debug("Processing subscribe message, root=%s, msgkey=%s", root, msg.key)
            # New consumer encryption key. Validate
            k,v = self._provisioners.reencrypt_request(root, cryptoexchange=self._cryptoexchange, msgkey=msg.key, msgval=msg.value)
            # Valid request, resign and retransmit
            if (not (k is None)) or (not (v is None)):
              self._logger.info("Valid consumer key request on topic=%s, root=%s, msgkey=%s. Resending to topic=%s, msgkey=%s", topic, root, msg.key, root + self.TOPIC_SUFFIX_REQS, k)
              self._kp.send((root + self.TOPIC_SUFFIX_REQS).decode('utf-8'), key=k, value=v)
            else:
              self._logger.info("Invalid consumer key request on topic=%s, root=%s in message: ", topic, root, msg)
          else:
            # unknown object
            self._logger.warning("Unknown topic type in message: %s", msg)
        self._lock.release()

      # Third, flush producer
      self._kp.flush()

      # Fourth, commit offsets
      if (self._kc.config['group_id'] is not None):
        self._kc.commit()
  
      # Finally, loop back to poll again
  # end of __process_mgmt_messages

