import copy
import inspect
import logging
from time import time
from threading import Lock
from confluent_kafka import Producer, Consumer, TopicPartition as TopicPartitionOffset, OFFSET_BEGINNING, OFFSET_END, TIMESTAMP_NOT_AVAILABLE, KafkaException, KafkaError
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
    self._producer._log.debug("Entering base callback with err=%s and msg=%s.", str(err), str(msg))
    if err is not None:
      self._producer._log.debug("Callback failed (non-None err).")
      super().failure(KafkaException(err))
    elif msg is None:
      self._producer._log.debug("Callback failed (None msg).")
      super().failure(KafkaException(KafkaError.UNKNOWN,'null msg'))
    elif msg.error() is not None:
      self._producer._log.debug("Callback failed (non-None msg.error).")
      super().failure(KafkaException(msg.error()))
    else:
      # success
      self._producer._log.debug("Callback success.")
      metadata = RecordMetadata(msg.topic(), msg.partition(), TopicPartition(msg.topic(), msg.partition()),
                                msg.offset(), msg.timestamp()[1] if msg.timestamp()[0]!=TIMESTAMP_NOT_AVAILABLE else int(time()*1000),
                                None, self.key_len, self.value_len, -1)
      super().success(metadata)
    self._producer._log.debug("Finished with base callback with err=%s and msg=%s.", str(err), str(msg))

  def get(self, timeout="default", timeout_jiffy=0.1):
    # timeout = None is infinite timeout, for compatibility with kafka-python's FutureRecordMetadata
    # timeout = "default" (or any non-number) should never be passed by callers, but is used here
    #           to indicate use of configured default.
    if timeout is None:
      last_time = 9223372036854775807
      timeout = last_time-time()
    elif timeout == "default":
      timeout = self._producer.config['produce_timeout']
      last_time = time()+timeout
    else:
      last_time = time()+timeout
    self._producer._log.debug("Entering FutureRecordMetadata get with timeout=%s.", str(timeout))
    orig_timeout = timeout
    while not self.is_done and timeout>0:
      self._producer.poll(min(timeout,timeout_jiffy))
      timeout = last_time-time()
      self._producer._log.debug("FutureRecordMetadata polling done, remaining timeout=%s.", str(timeout))
    if not self.is_done:
      raise FutureTimeoutError("Timeout after waiting for %s secs." % (orig_timeout,))
    if super().failed():
      raise self.exception
    self._producer._log.debug("Finished with FutureRecordMetadata get")
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

  def close(self):
    # confluent-kafka consumer causes crashes on close,
    # so this commits offsets and unsubscribes
    self.commit()
    self.unsubscribe()
    pass

  def _commit(self, offsets=None, asynchronous=False):
    self._log.debug("Executing Consumer commit.")
    try:
      if offsets==None:
        rv = super().commit(asynchronous=asynchronous)
      else:
        offs = []
        for k in offsets.keys():
          offs.append(TopicPartitionOffset(k.topic,k.partition,offsets[k].offset))
        rv = super().commit(offsets=offs,asynchronous=asynchronous)
    except KafkaException as ke:
      try:
        if ke.args[0].code() in [KafkaError._NO_OFFSET]:
          # ignore errors about committing offsets (means we have subscribed but not yet been assigned a particular topicpartition)
          # by doing this asynchronously. This matches the implicit kafka-python contract of not committing on topics
          # subscribed but not yet assigned.
          if offsets==None:
            return super().commit(asynchronous=True)
          else:
            return super().commit(offsets=offs,asynchronous=True)
        else:
          raise ke
      except:
        raise ke
    return rv

  def commit(self, offsets=None):
    return self._commit(offsets=offsets, asynchronous=False)

  def commit_async(self, offsets=None):
    # Right now callback is not implemented, so by leaving out of above we generate an exception
    # when a caller tries to use that functionality.
    return self._commit(offsets=offsets, asynchronous=True)

  def subscribe(self, topics=None, pattern=None, listener=None):
    self._log.info("Executing Consumer subscribe with topics=%s, pattern=%s, listener=%s", str(topics), str(pattern), str(listener))
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
    if (max_records is None) or max_records <= 0 or max_records > self.config['max_poll_records']:
      max_records = self.config['max_poll_records']
    self._log.debug("Entering Consumer poll with timeout_ms=%s and max_records=%s", str(timeout_ms), str(max_records))
    msgs = super().consume(max_records,timeout_ms/1000.0)
    self._log.debug("Consumer poll consume complete.")
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
    self._log.info("Executing Consumer assign with partitions=%s.", str(partitions))
    tps = []
    for tp in partitions:
      tps.append(TopicPartitionOffset(tp.topic, tp.partition))
    return super().assign(tps)

  def assign_and_seek(self, partoffs):
    self._log.info("Executing Consumer assign_and_seek with partoffs=%s.", str(partoffs))
    tps = []
    for tpo in partoffs:
      if (tpo.offset > 0) or (tpo.offset == OFFSET_BEGINNING) or (tpo.offset == OFFSET_END):
        tps.append(TopicPartitionOffset(tpo.topic, tpo.partition, tpo.offset))
      else:
        tps.append(TopicPartitionOffset(tpo.topic, tpo.partition))
    return super().assign(tps)

  def seek(self, tp, offset):
    self._log.debug("Executing Consumer seek.")
    return super().seek(TopicPartitionOffset(tp.topic, tp.partition, offset))

  def seek_to_beginning(self, tps=None):
    self._log.debug("Executing Consumer seek_to_beginning.")
    if tps is None or len(tps) < 1:
      tps = self.assignment()
    for tp in tps:
      try:
        self.seek(tp, OFFSET_BEGINNING)
      except:
        pass

  def seek_to_end(self, tps=None):
    self._log.debug("Executing Consumer seek_to_end.")
    if tps is None or len(tps) < 1:
      tps = self.assignment()
    for tp in tps:
      try:
        self.seek(tp, OFFSET_END)
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
  CONFIG_MAP_LOCAL = { 'produce_timeout': 30, # in s
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

  enable_flush_workaround = False

  def __init__(self, **configs):
    self._log = logging.getLogger(__name__)
    self.raw_config = configs
    self.cf_config = {}
    self.config = {}
    self.ks = lambda topic, _bytes: bytes(_bytes)
    self.vs = lambda topic, _bytes: bytes(_bytes)
    for k in self.CONFIG_MAP_LOCAL.keys():
      self.config[k] = self.CONFIG_MAP_LOCAL[k]
    for k in self.raw_config.keys():
      # adjust default produce_timeout if not separately set, and
      # other parameters are set that require it to adjust.
      if (k in ['delivery.timeout.ms', 'message.timeout.ms', 'transaction.timeout.ms']) and ('produce_timeout' not in self.raw_config.keys()):
        self.config['produce_timeout'] = self.raw_config[k]/1000.0
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
      elif (k in self.CONFIG_MAP_LOCAL):
        self.config[k] = self.raw_config[k]
      elif (k in self.CONFIG_MAP_NULL):
        self._log.warning("Warning: Unsupported kafka-python parameter passed to confluent wrapper: %s, %s", k, self.raw_config[k])
      else:
        self.cf_config[k] = self.raw_config[k]
    for oldk,newk in self.CONFIG_MAP.items():
      if newk in self.cf_config.keys():
        self.config[oldk] = self.cf_config[newk]
    self.messages_processed = 0
    self.messages_processed_lock = Lock()
    super().__init__(self.cf_config)
    if KafkaProducer.enable_flush_workaround:
      self.flush = self._flush_workaround
    else:
      self.flush = self._flush_native

  def close(self):
    # confluent-kafka has no concept of a "close" operation,
    # so this flushes queues only
    self.flush()
    pass

  def _flush_native(self, timeout="default", timeout_jiffy=0.1):
    if timeout is None:
      # confluent_kafka uses -1 for infinite timeout
      timeout = -1
    elif timeout == "default":
      timeout = self.config['produce_timeout']
    return super().flush(timeout)

  def _flush_workaround(self, timeout="default", timeout_jiffy=0.1):
    # librdkafka 1.8.0 changed the behavior of flush() to ignore linger_ms and
    # immediately attempt to send messages. Unfortunately, that change added
    # a call to rd_kafka_all_brokers_wakeup , which seems to cause a hang of
    # some type (perhaps a deadlock given the warning in kafka_all_brokers_wakeup
    # about making sure certain locks are not held?).
    #
    # This eventually results in non-sensical exceptions being thrown. We
    # fix it here by implementing flush as sucessive polling directly.
    #
    # timeout = None is infinite timeout
    # timeout = "default" (or any non-number) should never be passed by callers,
    #           but is used here to indicate use of configured default.
    #
    if timeout is None:
      # confluent_kafka uses -1 for infinite timeout
      timeout = -1
    elif timeout == "default":
      timeout = self.config['produce_timeout']
    with self.messages_processed_lock:
      left = len(self)
      final_processed = self.messages_processed+left
    initial = left
    self._log.debug("Entering Producer flush with timeout=%s and left=%s.", str(timeout), str(left))
    if timeout<0:
      while left > 0:
        con = self.poll(timeout_jiffy)
        initial -= con
        with self.messages_processed_lock:
          left = min([len(self),initial,max([0,final_processed-self.messages_processed])])
        self._log.debug("Producer flush poll cycle complete, left=%s.", str(left))
    elif left > 0:
      con = self.poll(timeout)
      initial -= con
      with self.messages_processed_lock:
        left = min([len(self),initial,max([0,final_processed-self.messages_processed])])
      self._log.debug("Producer flush single poll cycle complete, left=%s.", str(left))
    if max([left,0]) != 0:
      self._log.info("Producer flush complete, but messages left=%s greater than zero.", str(max([left,0])))
    else:
      self._log.debug("Producer flush complete.")
    return max([left,0])

  def poll(self, timeout=0):
    # timeout = 0 means nowait (default)
    # timeout = None means infinite timeout
    self._log.debug("Executing Producer poll with timeout=%s.", str(timeout))
    if timeout is None:
      # confluent_kafka uses -1 for infinite timeout
      timeout = -1
    rv = super().poll(timeout)
    if rv > 0:
      with self.messages_processed_lock:
        self.messages_processed += rv
    return rv

  def send(self, topic, value=None, key=None, headers=None, partition=0, timestamp_ms=None):
    self._log.debug("Executing Producer send to topic=%s, with value=%s, key=%s, headers=%s, partition=%s, timestamp_ms=%s.", str(topic), str(value), str(key), str(headers), str(partition), str(timestamp_ms))
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
