name='kafkacrypto'
# version and license information in setup.py
__all__ = []

import logging
try:
  import confluent_kafka
  from kafkacrypto.confluent_kafka_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset,OffsetAndMetadata
  logging.warning("Using confluent_kafka: %s, librdkafka: %s", confluent_kafka.version(), confluent_kafka.libversion())
except ImportError:
  # fallback to kafka-python
  logging.warning("No confluent_kafka package found. Falling back to kafka-python. It is highly")
  logging.warning("recommended that you install confluent_kafka and librdkafka for better performance,")
  logging.warning("especially with large messages.")
  from kafkacrypto.kafka_python_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset,OffsetAndMetadata
del logging

__all__.extend(['KafkaConsumer', 'KafkaProducer', 'TopicPartition', 'TopicPartitionOffset', 'OffsetAndMetadata'])

from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.crypto import KafkaCrypto
from kafkacrypto.controller import KafkaCryptoController
from kafkacrypto.kafkacryptostore import KafkaCryptoStore
from kafkacrypto.chainserver import KafkaCryptoChainServer
__all__.extend([ 'KafkaCryptoMessage', 'KafkaCrypto', 'KafkaCryptoStore', 'KafkaCryptoController', 'KafkaCryptoChainServer'])

