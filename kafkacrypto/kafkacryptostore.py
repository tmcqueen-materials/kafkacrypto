from kafka import KafkaConsumer as Consumer, KafkaProducer as Producer
from kafkacrypto.cryptostore import CryptoStore
import logging

class KafkaCryptoStore(CryptoStore):
  """This extends CryptoStore to be aware of how to read and prepare
     kafka configuration parameters, in addition to automatically configuring
     various common options. It serves to allow a user of kafkacrypto to
     manage *all* configuration with a single file if so desired.
         file (str): Specifies the backing file in which to read and
                     store configuration data. Must be readable, writable,
                     and seekable, with no other writers than one instance
                     of this class.
       nodeId (str): Optional manual specification of node_id. Useful only
                     if configuration data for many different nodes are
                     stored in a single file (see above for why you do NOT
                     want to do that), or if nodeId is not specified
                     in the configuration file.
  """
  def __init__(self, file, nodeId=None):
    if nodeId is None:
      super().__init__(file=file)
    else:
      super().__init__(nodeId,file)
    # set logging levels
    logging.basicConfig(level=self.load_value('log_level',default=logging.WARNING))
    logging.getLogger("kafkacrypto").setLevel(self.load_value('log_level',section='kafka-crypto',default=logging.INFO))

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
        kafka_config_filtered[key] = kafka_config[key]
      else:
        self._logger.warning("Filtering out %s:%s from kafka config.", str(key), str(kafka_config[key]))
    if 'group_id' in kafka_config and use!="consumer":
      kafka_config.pop('group_id',None)
    # do other producer/consumer filtering?
    return kafka_config
