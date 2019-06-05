import copy
import inspect
import logging
from confluent_kafka import Producer, Consumer, TopicPartition as CFTopicPartition, OFFSET_BEGINNING
from kafkacrypto.exceptions import KafkaCryptoWrapperError
from collections import namedtuple

TopicPartition = namedtuple("TopicPartition",
  ["topic", "partition"])
Message = namedtuple("Message",
  ["topic", "partition", "offset", "timestamp", "headers", "key", "value"])

class KafkaConsumer(Consumer):
  """
  Thin wrapper around confluent-kafka providing methods unique to kafka-python
  to allow them to be used interchangeably. Unless otherwise noted, parameters should
  be supplied as expected by the underlying confluent_kafka classes. Use at your own risk!
  """
  CONFIG_MAP = { 'ssl_cafile': 'ssl.ca.location',
                 'ssl_certfile': 'ssl.certificate.location',
                 'ssl_keyfile': 'ssl.key.location',
                 'ssl_crlfile': 'ssl.crl.location',
                 'ssl_password': 'ssl.key.password',
                 'ssl_ciphers': 'ssl.cipher.suites',
                 'max_request_size': 'message.max.bytes',
               }
  CONFIG_MAP_NULL = [ 'ssl_context', 'socket_options', 'max_partition_fetch_bytes' ]
  def __init__(self, *topics, **configs):
    self._log = logging.getLogger(__name__)
    self.config = configs
    self.cf_config = {}
    self.kds = lambda topic, _bytes: _bytes
    self.vds = lambda topic, _bytes: _bytes
    for k in self.config.keys():
      # For virtually all config parameters, kafka-python uses "_" everywhere confluent_kafka uses "."
      # so do that translation here if not "special". Some cannot be translated, for example:
      #  ssl_context
      #  socket_options
      #  max_partition_fetch_bytes
      if (k == 'key_deserializer'):
        if not (self.config[k] is None) and (not hasattr(self.config[k], 'deserialize') or not inspect.isroutine(self.config[k].deserialize)):
          self.kds = lambda topic, _bytes: self.config[k](_bytes)
        else:
          self.kds = self.config[k].deserialize
      elif (k == 'value_deserializer'):
        if not (self.config[k] is None) and (not hasattr(self.config[k], 'deserialize') or not inspect.isroutine(self.config[k].deserialize)):
          self.vds = lambda topic, _bytes: self.config[k](_bytes)
        else:
          self.vds = self.config[k].deserialize
      elif (k in self.CONFIG_MAP.keys()):
        if not (self.config[k] is None):
          self.cf_config[self.CONFIG_MAP[k]] = self.config[k]
      elif (k in self.CONFIG_MAP_NULL):
        self._log.warning("Warning: Unsupported kafka-python parameter passed to confluent wrapper: %s, %s", k, self.config[k])
      else:
        self.cf_config[k.replace('_','.')] = self.config[k]
    super().__init__(self.cf_config)
    if topics:
      self.subscribe(topics)

  def subscribe(self, topics=None, pattern=None, listener=None):
    if not topics is None:
      topics = copy.copy(topics)
    else:
      topics = []
    if not pattern is None:
      if pattern[0] != '^':
        topics.append('^' + pattern)
      else:
        topics.append(pattern)
    if listener is not None:
      return super().subscribe(topics, listener=listener)
    else:
      return super().subscribe(topics)

  def poll(self, timeout=None, timeout_ms=None, max_records=None):
    if not timeout_ms is None:
      timeout = timeout_ms/1000.0
    msg = super().poll(timeout)
    if not (msg is None) and msg.error() is None:
      rvk = TopicPartition(msg.topic(),msg.partition())
      rv = Message(rvk.topic, rvk.partition, msg.offset(), msg.timestamp(), msg.headers(), self.kds(rvk.topic,msg.key()), self.vds(rvk.topic,msg.value()))
      return {rvk:[rv]}
    else:
      return {}

  def assign(self, partitions):
    tps = []
    for tp in partitions:
      tps.append(CFTopicPartition(tp.topic, tp.partition))
    return super().assign(tps)

  def seek(self, tp, offset):
    return super().seek(CFTopicPartition(tp.topic, tp.partition, offset))

  def seek_to_beginning(self):
    for tp in self.assignment():
      self.seek(self, tp, OFFSET_BEGINNING)


class KafkaProducer(Producer):
  """
  Thin wrapper around confluent-kafka providing methods unique to kafka-python
  to allow them to be used interchangeably. Unless otherwise noted, parameters should
  be supplied as expected by the underlying confluent_kafka classes. Use at your own risk!
  """
  CONFIG_MAP = { 'ssl_cafile': 'ssl.ca.location',
                 'ssl_certfile': 'ssl.certificate.location',
                 'ssl_keyfile': 'ssl.key.location',
                 'ssl_crlfile': 'ssl.crl.location',
                 'ssl_password': 'ssl.key.password',
                 'ssl_ciphers': 'ssl.cipher.suites',
               }
  CONFIG_MAP_NULL = [ 'ssl_context', 'socket_options', 'max_partition_fetch_bytes' ]
  def __init__(self, **configs):
    self._log = logging.getLogger(__name__)
    self.config = configs
    self.cf_config = {}
    self.ks = lambda topic, _bytes: bytes(_bytes)
    self.vs = lambda topic, _bytes: bytes(_bytes)
    for k in self.config.keys():
      # For virtually all config parameters, kafka-python uses "_" everywhere confluent_kafka uses "."
      # so do that translation here if not "special". Some cannot be translated, for example:
      #  ssl_context
      #  socket_options
      #  max_partition_fetch_bytes
      if (k == 'key_serializer'):
        if not (self.config[k] is None) and (not hasattr(self.config[k], 'serialize') or not inspect.isroutine(self.config[k].serialize)):
          self.ks = lambda topic, _bytes: self.config[k](_bytes)
        else:
          self.ks = self.config[k].serialize
      elif (k == 'value_serializer'):
        if not (self.config[k] is None) and (not hasattr(self.config[k], 'serialize') or not inspect.isroutine(self.config[k].serialize)):
          self.vs = lambda topic, _bytes: self.config[k](_bytes)
        else:
          self.vs = self.config[k].serialize
      elif (k in self.CONFIG_MAP.keys()):
        if not (self.config[k] is None):
          self.cf_config[self.CONFIG_MAP[k]] = self.config[k]
      elif (k in self.CONFIG_MAP_NULL):
        self._log.warning("Warning: Unsupported kafka-python parameter passed to confluent wrapper: %s, %s", k, self.config[k])
      else:
        self.cf_config[k.replace('_','.')] = self.config[k]
    super().__init__(self.cf_config)

  def send(self, topic, value=None, key=None, headers=None, partition=0, timestamp_ms=None):
    if not (headers is None):
      return self.produce(topic,self.vs(topic, value),self.ks(topic, key),partition,lambda a,b: True, timestamp_ms, headers)
    elif not (timestamp_ms is None):
      return self.produce(topic,self.vs(topic, value),self.ks(topic, key),partition,lambda a,b: True, timestamp_ms)
    elif not (partition == 0):
      return self.produce(topic,self.vs(topic, value),self.ks(topic, key),partition)
    elif not (key is None):
      return self.produce(topic,self.vs(topic, value),self.ks(topic, key))
    elif not (value is None):
      return self.produce(topic,self.vs(topic, value))
    else:
      return self.produce(topic)
