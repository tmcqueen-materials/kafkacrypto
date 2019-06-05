name='kafkacrypto'
# version and license information in setup.py
__all__ = []

try:
  import confluent_kafka
  from kafkacrypto.confluent_kafka_wrapper import KafkaConsumer,KafkaProducer,TopicPartition
except ImportError:
  # fallback to kafka-python
  from kafka import KafkaConsumer,KafkaProducer,TopicPartition

__all__.extend(['KafkaConsumer', 'KafkaProducer', 'TopicPartition'])

from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.crypto import KafkaCrypto
from kafkacrypto.controller import KafkaCryptoController
__all__.extend([ 'KafkaCryptoMessage', 'KafkaCrypto', 'KafkaCryptoController'])

