import copy
import inspect
import logging
from time import time
from confluent_kafka import Producer, Consumer, TopicPartition as TopicPartitionOffset, OFFSET_BEGINNING, TIMESTAMP_NOT_AVAILABLE
from kafka.future import Future
from kafkacrypto.exceptions import KafkaCryptoWrapperError
from collections import namedtuple

TopicPartition = namedtuple("TopicPartition", ["topic", "partition"])
OffsetAndMetadata = namedtuple("OffsetAndMetadata", ["offset", "metadata"])
Message = namedtuple("Message",
  ["topic", "partition", "offset", "timestamp", "headers", "key", "value"])
RecordMetadata = namedtuple('RecordMetadata',
  ['topic', 'partition', 'topic_partition', 'offset', 'timestamp', 'checksum', 'serialized_key_size', 'serialized_value_size', 'serialized_header_size'])

class FutureTimeoutError(Exception):
  """
  Timeout waiting for future to complete
  """

class FutureRecordMetadata(Future):
  """
  Our implementation of FutureRecordMetadata so producer callbacks can be used
  """
  def __init__(self, producer, value_len, key_len):
    super().__init__()
    self._producer = producer
    self.key_len = key_len
    self.value_len = value_len

  def base_callback(self, err, msg):
    if err != None:
      self.failure(err)
    elif msg is None:
      self.failure('null msg')
    elif msg.error() != None:
      self.failure(msg.error())
    else:
      # success
      metadata = RecordMetadata(msg.topic(), msg.partition(), TopicPartition(msg.topic(), msg.partition()),
                                msg.offset(), msg.timestamp()[1] if msg.timestamp()[0]!=TIMESTAMP_NOT_AVAILABLE else int(time()*1000), 
                                None, self.key_len, self.value_len, -1)
      self.success(metadata)

  def get(self, timeout=None, timeout_jiffy=0.1):
    if timeout is None:
      last_time = 9223372036854775807
      timeout = last_time-time()
    else:
      last_time = time()+timeout
    while not self.is_done and timeout>0:
      self._producer.poll(min(timeout,timeout_jiffy))
      timeout = last_time-time()
    if not self.is_done:
      raise FutureTimeoutError("Timeout after waiting for %s secs." % (timeout,))
    if self.failed():
      raise self.exception
    return self.value


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
  CONFIG_MAP_LOCAL = { 'max_poll_records': 500,
                     }
  CONFIG_MAP_NULL = [ 'ssl_context', 
                      'socket_options', 
                      'default_offset_commit_callback', 
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
    for k in self.CONFIG_MAP_LOCAL.keys():
      self.config[k] = self.CONFIG_MAP_LOCAL[k]
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
      elif (k in self.CONFIG_MAP_LOCAL):
        self.config[k] = self.raw_config[k]
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

  def commit(self, offsets=None):
    if offsets==None:
      return super().commit()
    else:
      offs = []
      for k in offsets.keys():
        offs.append(TopicPartitionOffset(k.topic,k.partition,offsets[k].offset))
      return super().commit(offsets=offs)

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

  def poll(self, timeout_ms=0, max_records=None):
    rvm = {}
    msgs = super().consume(self.config['max_poll_records'],timeout_ms/1000.0)
    for msg in msgs:
      if not (msg is None) and msg.error() is None:
        rvk = TopicPartition(msg.topic(),msg.partition())
        rv = Message(rvk.topic, rvk.partition, msg.offset(), msg.timestamp(), msg.headers(), self.kds(rvk.topic,msg.key()), self.vds(rvk.topic,msg.value()))
        if rvk in rvm.keys():
          rvm[rvk].append(rv)
        else:
          rvm[rvk] = [rv]
    return rvm

  def assign(self, partitions):
    tps = []
    for tp in partitions:
      tps.append(TopicPartitionOffset(tp.topic, tp.partition))
    return super().assign(tps)

  def assign_and_seek(self, partoffs):
    tps = []
    for tpo in partoffs:
      if (tpo.offset > 0):
        tps.append(TopicPartitionOffset(tpo.topic, tpo.partition, tpo.offset))
      else:
        tps.append(TopicPartitionOffset(tpo.topic, tpo.partition))
    return super().assign(tps)

  def seek(self, tp, offset):
    return super().seek(TopicPartitionOffset(tp.topic, tp.partition, offset))

  def seek_to_beginning(self):
    for tp in self.assignment():
      try:
        self.seek(tp, OFFSET_BEGINNING)
      except:
        pass

  def __iter__(self):
    return self

  def __next__(self):
    rv = self.poll(timeout_ms=-1000.0,max_records=1)
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

  def poll(self, timeout=0):
    super().poll(timeout)

  def send(self, topic, value=None, key=None, headers=None, partition=0, timestamp_ms=None):
    if key!=None:
      key = self.ks(topic, key)
    if value!=None:
      value = self.vs(topic, value)
    rv = FutureRecordMetadata(self, len(value) if value!=None else -1, len(key) if key!=None else -1)
    # wish this were simpler, but the underlying library doesn't like None when no value should be passed.
    if key is None:
      key = b''
    if value is None:
      value = b''
    if not (headers is None):
      self.produce(topic, value, key, partition, rv.base_callback, timestamp_ms if timestamp_ms!=None else int(time()*1000), headers)
    elif not (timestamp_ms is None):
      self.produce(topic, value, key, partition, rv.base_callback, timestamp_ms)
    else:
      self.produce(topic, value, key, partition, rv.base_callback)
    return rv
