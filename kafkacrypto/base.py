from threading import Lock
import inspect
import msgpack
import logging
from kafkacrypto import KafkaProducer, KafkaConsumer
from kafkacrypto.exceptions import KafkaCryptoBaseError
from kafkacrypto.cryptokey import CryptoKey

class KafkaCryptoBase(object):
  """Base class for the handling the sending and receiving of encrypted messages.

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
         config (str,dict): Either a filename in which configuration
                            data is a stored, or a dict of config
                            parameters. Set to None to load from the
                            default location based on nodeID.
       cryptokey (str,obj): Either a filename in which the crypto
                            private key is stored, or an object 
                            implementing the necessary functions
                            (encrypt_keys, decrypt_keys, sign_spk,
                            load/store_crypto_opaque).
                            Set to None to use the default file
                            location based on nodeID.
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
               'MGMT_POLL_INTERVAL': 500,      # in ms
               'MGMT_POLL_RECORDS': 8,         # poll fetches by topic-partition. So limit number per call to sample all tps
               'MGMT_SUBSCRIBE_INTERVAL': 300, # in sec
               'MGMT_LONG_KEYINDEX': False,
             }

  def __init__(self, nodeID, kp, kc, config, cryptokey):
    if (not isinstance(nodeID, (str)) or len(nodeID) < 1):
      raise KafkaCryptoBaseError("Node ID " + str(nodeID) + " not a string or not specified!")
    if (not isinstance(kp, (KafkaProducer))):
      raise KafkaCryptoBaseError("Invalid Kafka Producer supplied!")
    if (not isinstance(kc, (KafkaConsumer))):
      raise KafkaCryptoBaseError("Invalid Kafka Consumer supplied!")
    if (config is None):
      config = nodeID + ".config"
    if (isinstance(config,(str,))):
      try:
        with open(config, 'rb') as config_file:
          config = msgpack.unpackb(config_file.read())
      except:
        config = {}
    self.__config(config)
    if (cryptokey is None):
      cryptokey = nodeID + ".crypto"
    if (isinstance(cryptokey,(str))):
      cryptokey = CryptoKey(file=cryptokey)
    if (not hasattr(cryptokey, 'decrypt_keys') or not inspect.isroutine(cryptokey.decrypt_keys) or not hasattr(cryptokey, 'encrypt_keys') or not inspect.isroutine(cryptokey.encrypt_keys) or
        not hasattr(cryptokey, 'signed_epk') or not inspect.isroutine(cryptokey.signed_epk) or not hasattr(cryptokey, 'load_crypto_opaque') or not inspect.isroutine(cryptokey.load_crypto_opaque) or
        not hasattr(cryptokey, 'store_crypto_opaque') or not inspect.isroutine(cryptokey.store_crypto_opaque)):
      raise KafkaCryptoBaseError("Invalid cryptokey source supplied!")

    self._nodeID = nodeID
    self._lock = Lock()
    self._kp = kp
    self._kc = kc
    self._cryptokey = cryptokey 
    self._logger = logging.getLogger(__name__)

  def __config(self, config):
    # config should be a map with names that we can override defaults with.
    for k in self.DEFAULTS.keys():
      v = self.DEFAULTS[k]
      if k in config.keys():
        v = config[k]
      elif (isinstance(k,(str,)) and k.encode('utf-8') in config.keys()):
        v = config[k.encode('utf-8')]
      setattr(self, k, v)

  def get_root(self,topic):
    root = topic.index(self.TOPIC_SEPARATOR)
    if (root != -1):
      root = topic[0:root]
    else:
      root = topic
    return root
