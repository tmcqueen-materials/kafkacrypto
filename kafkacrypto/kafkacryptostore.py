from kafka import KafkaConsumer as Consumer, KafkaProducer as Producer
from kafkacrypto.cryptostore import CryptoStore
import logging
from os import path

class KafkaCryptoStore(CryptoStore):
  """This extends CryptoStore to be aware of how to read and prepare
     kafka configuration parameters, in addition to automatically configuring
     various common options. It serves to allow a user of kafkacrypto to
     manage *all* configuration with a single file if so desired.
         file (str): Specifies the backing file in which to read and
                     store configuration data. Must be readable, writable,
                     and seekable, with no other writers than one instance
                     of this class.
       nodeID (str): Optional manual specification of node_id. Useful only
                     if configuration data for many different nodes are
                     stored in a single file (see above for why you do NOT
                     want to do that), or if nodeID is not specified
                     in the configuration file.
  """
  def __init__(self, file, nodeID=None):
    if nodeID is None:
      super().__init__(file=file)
    else:
      super().__init__(nodeID,file)
    if self._need_init:
      self.__init_kafkacryptostore()
    # set logging levels
    # This line ensures a default level if logger hasnt yet been used
    logging.basicConfig(level=self.load_value('log_level',default=logging.WARNING))
    # This line ensures a default level on the root logger if logger has been used
    logging.getLogger().setLevel(self.load_value('log_level',default=logging.WARNING))
    # This line sets the kafkacrypto logger level
    logging.getLogger("kafkacrypto").setLevel(self.load_value('log_level',section='crypto',default=logging.WARNING))
    # Check for CA list if not set
    if len(self.load_value('ssl_cafile',section='kafka',default='')) < 1:
      self._logger.warning("  Looking for system CA list.")
      if (path.exists("/etc/pki/tls/cert.pem")): # RHEL/CentOS
        ssl_cafile = "/etc/pki/tls/cert.pem"
      elif (path.exists("/usr/lib/ssl/certs/ca-certificates.crt")): # Debian/Ubuntu
        ssl_cafile = "/usr/lib/ssl/certs/ca-certificates.crt"
      else:
        try:
          import certifi
          ssl_cafile = certifi.where()
        except:
          ssl_cafile = ""
          self._logger.warning("    No system-wide CA list found. Update ssl_cafile in %s to point to a list of CAs that should be trusted for SSL/TLS endpoints.")
      self.store_value('ssl_cafile', ssl_cafile, section='kafka')

  def get_kafka_config(self, use, extra=None):
    # kafka parameters in 'kafka'
    # minimally contains:
    # bootstrap_server
    # security_protocol
    # if needed by chosen security_protocol:
    #   ssl_cafile
    # -- can have any other kafka configuration parameters
    #
    # kafkacrypto parameters in 'kafka-crypto'
    # minimally contains:
    # node_id (could be inherited from DEFAULT)
    # log_level (optional, default logging.INFO)
    # -- can have any other valid kafka configuration parameters to override those
    #    in the kafka section; set to blank here to unset a value.
    #    If not set here, group_id is set to "node_id + .kafkacrypto"
    #
    # Get kafka configuration
    kec = None
    kafka_config = self.load_section('kafka',defaults=False)
    extras = ['kafka-' + use]
    if extra!=None:
      extras.append('kafka-' + extra)
      extras.append('kafka-' + extra + '-' + use)
    for e in extras:
      kec = self.load_section(e,defaults=False)
      if kec != None:
        for k in kec:
          if k in kafka_config and len(kec[k]) == 0:
            kafka_config.pop(k, None)
          else:
            kafka_config[k] = kec[k]
    if 'group_id' not in kafka_config and use=="consumer":
      if extra == "crypto":
        kafka_config['group_id'] = self._nodeID + ".kafkacrypto";
      else:
        kafka_config['group_id'] = self._nodeID
    # Filter flags to those allowed by kafka producers or consumers
    # we do not limit based on the use case, so that appropriate
    # errors are generated if configurations are input incorrectly
    kafka_config_filtered = {}
    for key in kafka_config:
      if key in Consumer.DEFAULT_CONFIG or key in Producer.DEFAULT_CONFIG:
        kafka_config_filtered[key.replace('.','_')] = kafka_config[key]
      else:
        self._logger.warning("Filtering out %s:%s from kafka config.", str(key), str(kafka_config[key]))
    if 'group_id' in kafka_config and use!="consumer":
      kafka_config.pop('group_id',None)
    # do other producer/consumer filtering?
    return kafka_config

  def __init_kafkacryptostore(self):
    self.store_value('bootstrap_servers', '', section='kafka')
    self.store_value('security_protocol', 'SSL', section='kafka')
    self.store_value('test','test',section='kafka-consumer')
    self.store_value('test',None,section='kafka-consumer')
    self.store_value('test','test',section='kafka-producer')
    self.store_value('test',None,section='kafka-producer')
    self.store_value('test','test',section='kafka-crypto')
    self.store_value('test',None,section='kafka-crypto')
    self.store_value('test','test',section='kafka-crypto-consumer')
    self.store_value('test',None,section='kafka-crypto-consumer')
    self.store_value('test','test',section='kafka-crypto-producer')
    self.store_value('test',None,section='kafka-crypto-producer')

