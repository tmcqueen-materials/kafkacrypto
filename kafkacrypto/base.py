from threading import Lock
import inspect
import msgpack
import logging
import pysodium # only for legacy processing, removed in next version
from configparser import ConfigParser
from kafkacrypto import KafkaProducer, KafkaConsumer
from kafkacrypto.exceptions import KafkaCryptoBaseError
from kafkacrypto.cryptostore import CryptoStore
from kafkacrypto.cryptoexchange import CryptoExchange
from kafkacrypto.cryptokey import CryptoKey

class KafkaCryptoBase(object):
  """Base class for the handling the sending and receiving of encrypted messages.

  Keyword Arguments:
              nodeID (str): Node ID (can be None if specified in config file)
        kp (KafkaProducer): Pre-initialized KafkaProducer, ready for
                            handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
        kc (KafkaConsumer): Pre-initialized KafkaConsumer, ready for      
       	       	       	    handling crypto-keying messages. Should
                            not be used elsewhere, as this class
                            changes some configuration values.
     config (str,file,obj): Filename or File IO object in which
                            configuration data is stored. Set to None
                            to load from the default location based
                            on nodeID. Must be seekable, with read/
                            write permission, honor sync requests,
                            and not be written by any other program.
                            Can alternatively be an object implementing
                            the necessary functions to be a crypto
                            config store (load_section, load_value,
                            store_value, load_opaque_value, store_opaque_value,
                            set_cryptokey)
           cryptokey (obj): Optional object implementing the
                            necessary public/private key functions
                            (get/sign_spk,get/use_epk,
                            wrap/unwrap_opaque).
                            Set to None to load from the default
                            location in the configuration file.
  """

  #
  # Global configuration defaults
  #
  DEFAULTS = { 'TOPIC_SEPARATOR': '.',        # separator of topic name components, used to find root name and subs/keys
               'TOPIC_SUFFIX_SUBS': '.subs',  # suffixes should begin with separator or things will not work!
               'TOPIC_SUFFIX_KEYS': '.keys',
               'TOPIC_SUFFIX_REQS': '.reqs',
               'CRYPTO_MAX_PGEN_AGE': 604800,  # in s
               'CRYPTO_SUB_INTERVAL': 60,      # in s
               'CRYPTO_RATCHET_INTERVAL': 86400,  # in s
               'MGMT_TOPIC_CHAINS': 'chains',
               'MGMT_TOPIC_ALLOWLIST': 'allowlist',
               'MGMT_TOPIC_DENYLIST': 'denylist',
               'MGMT_FLUSH_TIME': 2,           # in s
               'MGMT_POLL_INTERVAL': 500,      # in ms
               'MGMT_POLL_RECORDS': 8,         # poll fetches by topic-partition. So limit number per call to sample all tps
               'MGMT_SUBSCRIBE_INTERVAL': 300, # in sec
               'MGMT_LONG_KEYINDEX': True,
               'DESER_INITIAL_WAIT_INTERVALS': 10,
             }

  def __init__(self, nodeID, kp, kc, config, cryptokey):
    if ((not isinstance(nodeID, (str)) or len(nodeID) < 1) and (nodeID!=None or config is None)):
      raise KafkaCryptoBaseError("Node ID " + str(nodeID) + " not a string or not specified!")
    if (not isinstance(kp, (KafkaProducer))):
      raise KafkaCryptoBaseError("Invalid Kafka Producer supplied!")
    if (not isinstance(kc, (KafkaConsumer))):
      raise KafkaCryptoBaseError("Invalid Kafka Consumer supplied!")
    if (config is None):
      config = nodeID + ".config"

    self._logger = logging.getLogger(__name__)

    if (hasattr(config, 'load_section') and inspect.isroutine(config.load_section) and
        hasattr(config, 'load_value') and inspect.isroutine(config.load_value) and
        hasattr(config, 'store_value') and inspect.isroutine(config.store_value) and
        hasattr(config, 'load_opaque_value') and inspect.isroutine(config.load_opaque_value) and
        hasattr(config, 'store_opaque_value') and inspect.isroutine(config.store_opaque_value) and
        hasattr(config, 'set_cryptokey') and inspect.isroutine(config.set_cryptokey)):
      self._cryptostore = config
    else:
      self._cryptostore = CryptoStore(nodeID, config)
    nodeID = self._cryptostore.get_nodeID()
    self.__configure()
    if (cryptokey is None):
      cryptokey = self._cryptostore.load_value('cryptokey')
      if cryptokey!=None and cryptokey.startswith('file#'):
        cryptokey = cryptokey[5:]
      if (cryptokey is None):
        cryptokey = nodeID + '.crypto'
        self._cryptostore.store_value('cryptokey', 'file#' + cryptokey)
    if (isinstance(cryptokey,(str))):
      cryptokey = CryptoKey(file=cryptokey)
    if (not hasattr(cryptokey, 'get_spk') or not inspect.isroutine(cryptokey.get_spk) or not hasattr(cryptokey, 'sign_spk') or not inspect.isroutine(cryptokey.sign_spk) or
        not hasattr(cryptokey, 'get_epk') or not inspect.isroutine(cryptokey.get_epk) or not hasattr(cryptokey, 'use_epk') or not inspect.isroutine(cryptokey.use_epk) or
        not hasattr(cryptokey, 'wrap_opaque') or not inspect.isroutine(cryptokey.wrap_opaque) or not hasattr(cryptokey, 'unwrap_opaque') or not inspect.isroutine(cryptokey.unwrap_opaque)):
      raise KafkaCryptoBaseError("Invalid cryptokey source supplied!")
    self._cryptokey = cryptokey
    self._cryptostore.set_cryptokey(self._cryptokey)

    # Attempt legacy rot/chainrot load
    rot = self._cryptostore.load_value('rot',section="crypto")
    if rot!=None:
      self._cryptostore.store_value('rot',rot,section='allowlist')
      self._cryptostore.store_value('rot',None,section='crypto')
    chainrot = self._cryptostore.load_value('chainrot',section='crypto')
    if chainrot!=None:
      if rot != chainrot:
        self._cryptostore.store_value('chainrot',chainrot,section='allowlist')
      self._cryptostore.store_value('chainrot',None,section='crypto')

    allowlist = self._cryptostore.load_section('allowlist',defaults=False)
    if not (allowlist is None):
      allowlist = allowlist.values()
    denylist = self._cryptostore.load_section('denylist',defaults=False)
    if not (denylist is None):
      denylist = denylist.values()
    self._cryptoexchange = CryptoExchange(self._cryptostore.load_value('chain',section='crypto'),self._cryptokey,
                           maxage=self._cryptostore.load_value('maxage',section='crypto'),allowlist=allowlist,denylist=denylist)

    self._nodeID = nodeID
    self._lock = Lock()
    self._kp = kp
    self._kc = kc

  def __configure(self):
    for k in self.DEFAULTS.keys():
      v = self.DEFAULTS[k]
      v2 = self._cryptostore.load_value(k)
      self._logger.info("Loading config: %s,%s,%s",k,v,v2)
      if isinstance(v2, (bytes,bytearray)):
        v2s = v2.decode('utf-8')
        self._logger.warning("Migrating config from bytes to str: %s,%s,%s->%s",k,v,v2,v2s)
        v2 = v2s
      setattr(self, k, v2 if v2!=None else v)

  def get_root(self,topic):
    wasbytes = False
    if isinstance(topic,(bytes,bytearray)):
      self._logger.debug("get_root called with topic as bytes (should be string)")
      wasbytes = True
      topic = topic.decode('utf-8')
    root = topic.find(self.TOPIC_SEPARATOR)
    if (root != -1):
      root = topic[0:root]
    else:
      root = topic
    if wasbytes:
      root = root.encode('utf-8')
    return root
