name='kafkacrypto'
# version and license information in setup.py
__all__ = []

try:
  import confluent_kafka
  from kafkacrypto.confluent_kafka_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset
except ImportError:
  # fallback to kafka-python
  from kafkacrypto.kafka_python_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset

__all__.extend(['KafkaConsumer', 'KafkaProducer', 'TopicPartition', 'TopicPartitionOffset'])

from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.crypto import KafkaCrypto
from kafkacrypto.controller import KafkaCryptoController
from kafkacrypto.kafkacryptostore import KafkaCryptoStore
__all__.extend([ 'KafkaCryptoMessage', 'KafkaCrypto', 'KafkaCryptoStore', 'KafkaCryptoController'])

