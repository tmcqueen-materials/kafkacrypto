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
  DEFAULTS = { 'TOPIC_SEPARATOR': b'.',        # separator of topic name components, used to find root name and subs/keys
               'TOPIC_SUFFIX_SUBS': b'.subs',  # suffixes should begin with separator or things will not work!
               'TOPIC_SUFFIX_KEYS': b'.keys',
               'TOPIC_SUFFIX_REQS': b'.reqs',
               'CRYPTO_MAX_PGEN_AGE': 604800,  # in s
               'CRYPTO_SUB_INTERVAL': 60,      # in s
               'CRYPTO_RATCHET_INTERVAL': 86400,  # in s
               'MGMT_TOPIC_CHAINS': b'chains',
               'MGMT_TOPIC_DENYLIST': b'denylist',
               'MGMT_POLL_INTERVAL': 500,      # in ms
               'MGMT_POLL_RECORDS': 8,         # poll fetches by topic-partition. So limit number per call to sample all tps
               'MGMT_SUBSCRIBE_INTERVAL': 300, # in sec
               'MGMT_LONG_KEYINDEX': False,
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

    try:
      # Handle legacy file format. Everything inside this try block will go
      # away in the next version and legacy files will no longer work.
      with open(config, 'rb') as config_file:
        config_old = msgpack.unpackb(config_file.read())
      self._logger.warning("Legacy file format detected. Converting to new form.")
      config_file = open(config, 'w+')
      self._cryptostore = CryptoStore(nodeID, config)
      for k in config_old.keys():
        ks = k if isinstance(k,(str,)) else k.decode('utf-8')
        self._cryptostore.store_value(ks,config_old[k])
      if (cryptokey is None):
        self._logger.warning("Converting legacy %s", nodeID+'.crypto')
        self._cryptostore.store_value('cryptokey','file#' + nodeID + '.crypto')
        with open(nodeID+'.crypto','rb') as old_cf:
          data = old_cf.read()
          contents = None
          while len(data) and contents is None:
            try:
              contents = msgpack.unpackb(data)
            except msgpack.exceptions.ExtraData:
              data = data[:-1]
        if len(contents) >= 5:
          with open(nodeID+'.crypto','wb') as old_cf:
            old_cf.write(msgpack.packb([contents[3],pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)]))
          self._cryptostore.store_value('maxage',contents[0],section="crypto")
          self._cryptostore.store_value('rot',contents[1],section="crypto")
          self._cryptostore.store_value('chainrot',contents[2],section="crypto")
          self._cryptostore.store_value('chain',contents[4],section="crypto")
          self._cryptokey = CryptoKey(file=nodeID+".crypto")
          self._cryptostore.set_cryptokey(self._cryptokey)
          if len(contents) >= 6:
            self._cryptostore.store_opaque_value('oldkeys',msgpack.packb(msgpack.unpackb(contents[5])[0]),section="crypto")
      self._logger.warning("Conversion from legacy to new form complete.")
      self.__configure()
    except:
      if (hasattr(config, 'load_section') and inspect.isroutine(config.load_section) and
          hasattr(config, 'load_value') and inspect.isroutine(config.load_value) and
          hasattr(config, 'store_value') and inspect.isroutine(config.store_value) and
          hasattr(config, 'load_opaque_value') and inspect.isroutine(config.load_opaque_value) and
          hasattr(config, 'store_opaque_value') and inspect.isroutine(config.store_opaque_value) and
          hasattr(config, 'set_cryptokey') and inspect.isroutine(config.set_cryptokey)):
        self._cryptostore = config
      else:
        self._cryptostore = CryptoStore(nodeID, config)
      self.__configure()
      if (cryptokey is None):
        cryptokey = self._cryptostore.load_value('cryptokey')
        if cryptokey.startswith('file#'):
          cryptokey = cryptokey[5:]
      if (isinstance(cryptokey,(str))):
        cryptokey = CryptoKey(file=cryptokey)
      if (not hasattr(cryptokey, 'get_spk') or not inspect.isroutine(cryptokey.get_spk) or not hasattr(cryptokey, 'sign_spk') or not inspect.isroutine(cryptokey.sign_spk) or
          not hasattr(cryptokey, 'get_epk') or not inspect.isroutine(cryptokey.get_epk) or not hasattr(cryptokey, 'use_epk') or not inspect.isroutine(cryptokey.use_epk) or
          not hasattr(cryptokey, 'wrap_opaque') or not inspect.isroutine(cryptokey.wrap_opaque) or not hasattr(cryptokey, 'unwrap_opaque') or not inspect.isroutine(cryptokey.unwrap_opaque)):
        raise KafkaCryptoBaseError("Invalid cryptokey source supplied!")
      self._cryptokey = cryptokey
      self._cryptostore.set_cryptokey(self._cryptokey)

    denylist = self._cryptostore.load_section('denylist')
    if not (denylist is None):
      denylist = denylist.values()
    self._cryptoexchange = CryptoExchange(self._cryptostore.load_value('rot',section="crypto"),self._cryptostore.load_value('chainrot',section="crypto"),self._cryptostore.load_value('chain',section="crypto"),self._cryptokey,
                           maxage=self._cryptostore.load_value('maxage',section="crypto"),denylist=denylist)

    self._nodeID = nodeID
    self._lock = Lock()
    self._kp = kp
    self._kc = kc

  def __configure(self):
    for k in self.DEFAULTS.keys():
      v = self.DEFAULTS[k]
      v2 = self._cryptostore.load_value(k)
      setattr(self, k, v2 if v2!=None else v)

  def get_root(self,topic):
    root = topic.index(self.TOPIC_SEPARATOR)
    if (root != -1):
      root = topic[0:root]
    else:
      root = topic
    return root
