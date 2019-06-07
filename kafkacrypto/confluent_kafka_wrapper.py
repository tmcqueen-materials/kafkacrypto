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
                 'max_partition_fetch_bytes': 'message.max.bytes', # this maps the hard limit functionality appropriately
                 'bootstrap_servers': 'bootstrap.servers',
                 'client_id': 'client.id',
                 'group_id': 'group.id',
                 'fetch_min_bytes': 'fetch.min.bytes',
                 'fetch_max_wait_ms': 'fetch.wait.max.ms',
                 'fetch_max_bytes': 'fetch.max.bytes',
                 'request_timeout_ms': 'request.timeout.ms',
                 'retry_backoff_ms': 'retry.backoff.ms',
                 'reconnect_backoff_ms': 'reconnect.backoff.ms',
                 'reconnect_backoff_max_ms': 'reconnect.backoff.max.ms',
                 'max_in_flight_requests_per_connection': 'max.in.flight.requests.per.connection',
                 'auto_offset_reset': 'auto.offset.reset',
                 'enable_auto_commit': 'enable.auto.commit',
                 'auto_commit_interval_ms': 'auto.commit.interval.ms',
                 'check_crcs': 'check.crcs',
                 'metadata_max_age_ms': 'metadata.max.age.ms',
                 'partition_assignment_strategy': 'partition.assignment.strategy',
                 'max_poll_interval_ms': 'max.poll.interval.ms',
                 'session_timeout_ms': 'session.timeout.ms',
                 'heartbeat_interval_ms': 'heartbeat.interval.ms',
                 'receive_buffer_bytes': 'socket.receive.buffer.bytes',
                 'send_buffer_bytes': 'socket.send.buffer.bytes',
                 'security_protocol': 'security.protocol',
                 'sasl_mechanism': 'sasl.mechanism',
                 'sasl_plain_username': 'sasl.username',
                 'sasl_plain_password': 'sasl.password',
                 'sasl_kerberos_service_name': 'sasl.kerberos.service.name',
               }
  CONFIG_MAP_NULL = [ 'ssl_context', 
                      'socket_options', 
                      'default_offset_commit_callback', 
                      'max_poll_records', 
                      'consumer_timeout_ms',
                      'ssl_check_hostname',
                      'api_version',
                      'api_version_auto_timeout_ms',
                      'connections_max_idle_ms',
                      'metrics_reporters',
                      'metrics_num_samples',
                      'metrics_sample_window_ms',
                      'selector',
                      'exclude_internal_topics',
                      'sasl_kerberos_domain_name',
                      'sasl_oauth_token_provider',
                    ]
  def __init__(self, *topics, **configs):
    self._log = logging.getLogger(__name__)
    self.raw_config = configs
    self.cf_config = {}
    self.config = {}
    self.kds = lambda topic, _bytes: _bytes
    self.vds = lambda topic, _bytes: _bytes
    for k in self.raw_config.keys():
      if (k == 'key_deserializer'):
        if not (self.raw_config[k] is None) and (not hasattr(self.raw_config[k], 'deserialize') or not inspect.isroutine(self.raw_config[k].deserialize)):
          self.kds = lambda topic, _bytes: self.raw_config[k](_bytes)
        else:
          self.kds = self.raw_config[k].deserialize
        self.config[k] = self.kds
      elif (k == 'value_deserializer'):
        if not (self.raw_config[k] is None) and (not hasattr(self.raw_config[k], 'deserialize') or not inspect.isroutine(self.raw_config[k].deserialize)):
          self.vds = lambda topic, _bytes: self.raw_config[k](_bytes)
        else:
          self.vds = self.raw_config[k].deserialize
        self.config[k] = self.vds
      elif (k in self.CONFIG_MAP.keys()):
        if not (self.raw_config[k] is None):
          self.cf_config[self.CONFIG_MAP[k]] = self.raw_config[k]
      elif (k in self.CONFIG_MAP_NULL):
        self._log.warning("Warning: Unsupported kafka-python parameter passed to confluent wrapper: %s, %s", k, self.raw_config[k])
      else:
        self.cf_config[k] = self.raw_config[k]
    for oldk,newk in self.CONFIG_MAP.items():
      if newk in self.cf_config.keys():
        self.config[oldk] = self.cf_config[newk]
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
    else:
      msg = super().poll()
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
      try:
        self.seek(tp, OFFSET_BEGINNING)
      except:
        pass

  def __iter__(self):
    return self

  def __next__(self):
    rv = self.poll(max_records=1)
    if len(rv) == 1:
      return list(rv.values())[0][0]
    raise StopIteration("Poll Failed!")

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
                 'max_request_size': 'message.max.bytes', # this maps the hard limit functionality appropriately                                                 
                 'bootstrap_servers': 'bootstrap.servers',
                 'client_id': 'client.id',
                 'group_id': 'group.id',
                 'acks': 'request.required.acks',
                 'compression_type': 'compression.type',
                 'retries': 'message.send.max.retries',
                 'linger_ms': 'queue.buffering.max.ms',
                 'request_timeout_ms': 'request.timeout.ms',
                 'retry_backoff_ms': 'retry.backoff.ms',
                 'reconnect_backoff_ms': 'reconnect.backoff.ms',
                 'reconnect_backoff_max_ms': 'reconnect.backoff.max.ms',
                 'max_in_flight_requests_per_connection': 'max.in.flight.requests.per.connection',
                 'metadata_max_age_ms': 'metadata.max.age.ms',
                 'receive_buffer_bytes': 'socket.receive.buffer.bytes',
                 'send_buffer_bytes': 'socket.send.buffer.bytes',
                 'security_protocol': 'security.protocol',
                 'sasl_mechanism': 'sasl.mechanism',
                 'sasl_plain_username': 'sasl.username',
                 'sasl_plain_password': 'sasl.password',
                 'sasl_kerberos_service_name': 'sasl.kerberos.service.name',
               }
  CONFIG_MAP_NULL = [ 'ssl_context', 
                      'socket_options',
                      'batch_size',
                      'partitioner',
                      'buffer_memory',
                      'connections_max_idle_ms',
                      'max_block_ms',
                      'ssl_check_hostname',
                      'api_version',
                      'api_version_auto_timeout_ms',
                      'metrics_reporters',
                      'metrics_num_samples',
                      'metrics_sample_window_ms',
                      'selector',
                      'sasl_kerberos_domain_name',
                      'sasl_oauth_token_provider',
                    ]
  def __init__(self, **configs):
    self._log = logging.getLogger(__name__)
    self.raw_config = configs
    self.cf_config = {}
    self.config = {}
    self.ks = lambda topic, _bytes: bytes(_bytes)
    self.vs = lambda topic, _bytes: bytes(_bytes)
    for k in self.raw_config.keys():
      if (k == 'key_serializer'):
        if not (self.raw_config[k] is None) and (not hasattr(self.raw_config[k], 'serialize') or not inspect.isroutine(self.raw_config[k].serialize)):
          self.ks = lambda topic, _bytes: self.raw_config[k](_bytes)
        else:
          self.ks = self.raw_config[k].serialize
        self.config[k] = self.ks
      elif (k == 'value_serializer'):
        if not (self.raw_config[k] is None) and (not hasattr(self.raw_config[k], 'serialize') or not inspect.isroutine(self.raw_config[k].serialize)):
          self.vs = lambda topic, _bytes: self.raw_config[k](_bytes)
        else:
          self.vs = self.raw_config[k].serialize
        self.config[k] = self.vs
      elif (k in self.CONFIG_MAP.keys()):
        if not (self.raw_config[k] is None):
          self.cf_config[self.CONFIG_MAP[k]] = self.raw_config[k]
      elif (k in self.CONFIG_MAP_NULL):
        self._log.warning("Warning: Unsupported kafka-python parameter passed to confluent wrapper: %s, %s", k, self.raw_config[k])
      else:
        self.cf_config[k] = self.raw_config[k]
    for oldk,newk in self.CONFIG_MAP.items():
      if newk in self.cf_config.keys():
        self.config[oldk] = self.cf_config[newk]
    super().__init__(self.cf_config)

  def send(self, topic, value=None, key=None, headers=None, partition=0, timestamp_ms=None):
    # wish this were simpler, but the underlying library doesn't like None when no value should be passed.
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
