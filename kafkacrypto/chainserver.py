#!/usr/bin/python3
from threading import Thread
from time import time, sleep
from kafkacrypto import KafkaProducer
from kafkacrypto.exceptions import KafkaCryptoChainServerError
from kafkacrypto.chain import process_chain
from kafkacrypto.cryptokey import CryptoKey
from kafkacrypto.cryptostore import CryptoStore
import msgpack
import inspect
import logging
from kafkacrypto.utils import format_exception_shim

class KafkaCryptoChainServer(object):
  """ A simple chain server implementation, regularly producing new
      chains for authorized prod/cons using our key (signed by ROT).

  Keyword Arguments:
              nodeID (str): Node ID (optional if config specified)
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

  def __init__(self, nodeID, config=None, cryptokey=None):
    if ((not isinstance(nodeID, (str)) or len(nodeID) < 1) and (nodeID!=None or config is None)):
      raise KafkaCryptoChainServerError("Node ID " + str(nodeID) + " not a string or not specified!")
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
    self._nodeID = nodeID

    if (cryptokey is None):
      cryptokey = self._cryptostore.load_value('cryptokey')
      if cryptokey.startswith('file#'):
        cryptokey = cryptokey[5:]
    if (isinstance(cryptokey,(str))):
      cryptokey = CryptoKey(file=cryptokey)
    if (not hasattr(cryptokey, 'get_spk') or not inspect.isroutine(cryptokey.get_spk) or not hasattr(cryptokey, 'sign_spk') or not inspect.isroutine(cryptokey.sign_spk) or
        not hasattr(cryptokey, 'get_epk') or not inspect.isroutine(cryptokey.get_epk) or not hasattr(cryptokey, 'use_epk') or not inspect.isroutine(cryptokey.use_epk) or
        not hasattr(cryptokey, 'wrap_opaque') or not inspect.isroutine(cryptokey.wrap_opaque) or not hasattr(cryptokey, 'unwrap_opaque') or not inspect.isroutine(cryptokey.unwrap_opaque)):
      raise KafkaCryptoChainServerError("Invalid cryptokey source supplied!")
    self._cryptokey = cryptokey
    self._cryptostore.set_cryptokey(self._cryptokey)

    # Load our custom configuration
    self._interval_secs = self._cryptostore.load_value('interval_secs', default=300)
    self._lifetime = self._cryptostore.load_value('lifetime', default=604800)
    self._refresh_fraction = self._cryptostore.load_value('refresh_fraction', default=0.143)
    self._flush_time = self._cryptostore.load_value('flush_time', default=2.0)

    # Load our signing key and trimmings
    self._our_chain = self._cryptostore.load_value('chain',section='crypto')
    try:
      msgpack.unpackb(self._our_chain, raw=False)
    except:
      self._logger.warning("Chain server chain is in legacy format. This should be corrected.")
      self._our_chain = msgpack.packb(msgpack.unpackb(self._our_chain,raw=True),use_bin_type=True)
    self._allowlist = self._cryptostore.load_section('allowlist',defaults=False)
    if not (self._allowlist is None):
      self._allowlist = self._allowlist.values()

    # Validate
    pk,pkprint = process_chain(self._our_chain,None,None,allowlist=self._allowlist)
    if (pk[2] != self._cryptokey.get_spk()):
      raise KafkaCryptoChainServerError("Chain does not match public key: " + str(pkprint))

    # Connect to Kafka
    self._producer = KafkaProducer(**self._cryptostore.get_kafka_config('producer'))

    # Run Thread
    self._mgmt_thread = Thread(target=self._chain_server,daemon=True)
    self._mgmt_thread.start()

  def _chain_server(self):
    while True:
      self._logger.info("Checking Key Lifetimes")
      chainkeys = self._cryptostore.load_section('chainkeys',defaults=False)
      for ck in chainkeys.keys():
        cv = msgpack.unpackb(chainkeys[ck],raw=True)
        self._logger.info("Checking Key: %s", cv[2])
        if cv[0]<time()+self._lifetime*self._refresh_fraction:
          try:
            # Time to renew this key
            self._logger.warning("Key expires soon, renewing %s", cv)
            msg = msgpack.packb([time()+self._lifetime,cv[1],cv[2]], use_bin_type=True)
            chain = self._cryptokey.sign_spk(msg)
            chain = msgpack.packb(msgpack.unpackb(self._our_chain,raw=False) + [chain], use_bin_type=True)
            # Validate
            pk,_ = process_chain(chain,None,None,allowlist=self._allowlist)
            # Broadcast
            self._producer.send('chains',key=cv[2],value=chain)
            self._producer.flush(timeout=self._flush_time)
            # save
            self._cryptostore.store_value(ck,msg,section='chainkeys')
          except Exception as e:
            self._logger.warning("".join(format_exception_shim(e)))
      self._logger.info("Done Checking.")
      sleep(self._interval_secs)
