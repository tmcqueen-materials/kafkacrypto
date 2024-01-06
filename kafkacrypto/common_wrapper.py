try:
  from kafka.future import Future as Future
except ImportError:
  import logging
  #
  # kafka-python compatible implementation of Future
  #
  class Future(object):
    done = False
    value = None
    exception = None
    exceptions_on_callbacks = False
    callbacks = []
    errorbacks = []

    def __init__(self):
      self._log = logging.getLogger(__name__)

    def retriable(self):
      try:
        return self.exception.retriable
      except:
        return False

    def success(self, val):
      assert not self.done, 'Future already completed'
      self.value = val
      self.done = True
      if self.callbacks:
        self.call_backs('callback', self.callbacks, self.value)
      return self

    def succeeded(self):
      return self.done and not bool(self.exception)

    def failure(self, e):
      assert not self.done, 'Future already completed'
      self.exception = e if type(e) is not type else e()
      assert isinstance(self.exception, BaseException), 'Future failed with no exception'
      self.done = True
      self.call_backs('errorback', self.errorbacks, self.exception)
      return self

    def failed(self):
      return self.done and bool(self.exception)

    def add_callback(self, f, *args, **kwargs):
      if args or kwargs:
        f = functools.partial(f, *args, **kwargs)
      # Execute immediately if done (without error), otherwise queue for when completed
      if self.done and not self.exception:
        self.call_backs('callback', [f], self.value)
      else:
        self.callbacks.append(f)
      return self

    def add_errback(self, f, *args, **kwargs):
      if args or kwargs:
        f = functools.partial(f, *args, **kwargs)
      # Execute immediately if done (with error), otherwise queue for later
      if self.done and self.exception:
        self.call_backs('errorback', [f], self.exception)
      else:
        self.errorbacks.append(f)
      return self

    def add_both(self, f, *args, **kwargs):
      self.add_callback(f, *args, **kwargs)
      self.add_errback(f, *args, **kwargs)
      return self

    def chain(self, future):
      self.add_callback(future.success)
      self.add_errback(future.failure)
      return self

    def call_backs(self, back_type, backs, value):
      for f in backs:
        try:
          f(value)
        except Exception as e:
          self._log.exception('Error processing %s', back_type)
          if self.exceptions_on_callbacks:
            raise e

try:
  from kafka.serializer import Deserializer as AbstractDeserializer, Serializer as AbstractSerializer
except ImportError:
  #
  # Abstract versions of SerDes
  #
  import abc

  class AbstractDeserializer(object):
    __meta__ = abc.ABCMeta

    def __init__(self, **config):
      pass

    @abc.abstractmethod
    def deserialize(self, topic, bytes_):
      pass

    def close(self):
      pass

  class AbstractSerializer(object):
    __meta__ = abc.ABCMeta

    def __init__(self, **config):
      pass

    @abc.abstractmethod
    def serialize(self, topic, value):
      pass

    def close(self):
      pass

#
# Configuration option names
# TODO: list confluent-kafka only options so they are not filtered out
#
PRODUCER_CONFIGS = [
  'bootstrap_servers',
  'client_id',
  'key_serializer',
  'value_serializer',
  'acks',
  'bootstrap_topics_filter',
  'compression_type',
  'retries',
  'batch_size',
  'linger_ms',
  'partitioner',
  'buffer_memory',
  'connections_max_idle_ms',
  'max_block_ms',
  'max_request_size',
  'metadata_max_age_ms',
  'retry_backoff_ms',
  'request_timeout_ms',
  'receive_buffer_bytes',
  'send_buffer_bytes',
  'socket_options',
  'reconnect_backoff_ms',
  'reconnect_backoff_max_ms',
  'max_in_flight_requests_per_connection',
  'security_protocol',
  'ssl_context',
  'ssl_check_hostname',
  'ssl_cafile',
  'ssl_certfile',
  'ssl_keyfile',
  'ssl_crlfile',
  'ssl_password',
  'ssl_ciphers',
  'api_version',
  'api_version_auto_timeout_ms',
  'metric_reporters',
  'metrics_num_samples',
  'metrics_sample_window_ms',
  'selector',
  'sasl_mechanism',
  'sasl_plain_username',
  'sasl_plain_password',
  'sasl_kerberos_service_name',
  'sasl_kerberos_domain_name',
  'sasl_oauth_token_provider',
]

CONSUMER_CONFIGS = [
  'bootstrap_servers',
  'client_id',
  'group_id',
  'key_deserializer',
  'value_deserializer',
  'fetch_max_wait_ms',
  'fetch_min_bytes',
  'fetch_max_bytes',
  'max_partition_fetch_bytes',
  'request_timeout_ms',
  'retry_backoff_ms',
  'reconnect_backoff_ms',
  'reconnect_backoff_max_ms',
  'max_in_flight_requests_per_connection',
  'auto_offset_reset',
  'enable_auto_commit',
  'auto_commit_interval_ms',
  'default_offset_commit_callback',
  'check_crcs',
  'metadata_max_age_ms',
  'partition_assignment_strategy',
  'max_poll_records',
  'max_poll_interval_ms',
  'session_timeout_ms',
  'heartbeat_interval_ms',
  'receive_buffer_bytes',
  'send_buffer_bytes',
  'socket_options',
  'consumer_timeout_ms',
  'security_protocol',
  'ssl_context',
  'ssl_check_hostname',
  'ssl_cafile',
  'ssl_certfile',
  'ssl_keyfile',
  'ssl_crlfile',
  'ssl_password',
  'ssl_ciphers',
  'api_version',
  'api_version_auto_timeout_ms',
  'connections_max_idle_ms',
  'metric_reporters',
  'metrics_num_samples',
  'metrics_sample_window_ms',
  'metric_group_prefix',
  'selector',
  'exclude_internal_topics',
  'sasl_mechanism',
  'sasl_plain_username',
  'sasl_plain_password',
  'sasl_kerberos_service_name',
  'sasl_kerberos_domain_name',
  'sasl_oauth_token_provider',
  'legacy_iterator',
]

