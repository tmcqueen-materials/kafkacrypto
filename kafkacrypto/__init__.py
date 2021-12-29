name='kafkacrypto'
# version and license information in setup.py
__all__ = []

#
# Use warnings to not accidentally initialize the logging subsystem (these can and will
# be logged to a logger if logger is configured with captureWarnings). The category
# is RuntimeWarning because that is where information about library configurations
# should be sent.
#
import warnings
try:
  import confluent_kafka
  from kafkacrypto.confluent_kafka_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset,OffsetAndMetadata
  warnings.warn("Using confluent_kafka: {}, librdkafka: {}".format(str(confluent_kafka.version()), str(confluent_kafka.libversion())),category=RuntimeWarning)
except ImportError:
  # fallback to kafka-python
  warnings.warn("No confluent_kafka package found. Falling back to kafka-python. It is highly, recommended that you install confluent_kafka and librdkafka for better performance, especially with large messages.",category=RuntimeWarning)
  from kafkacrypto.kafka_python_wrapper import KafkaConsumer,KafkaProducer,TopicPartition,TopicPartitionOffset,OffsetAndMetadata
del warnings

__all__.extend(['KafkaConsumer', 'KafkaProducer', 'TopicPartition', 'TopicPartitionOffset', 'OffsetAndMetadata'])

from kafkacrypto.message import KafkaCryptoMessage
from kafkacrypto.crypto import KafkaCrypto
from kafkacrypto.controller import KafkaCryptoController
from kafkacrypto.kafkacryptostore import KafkaCryptoStore
from kafkacrypto.chainserver import KafkaCryptoChainServer
__all__.extend([ 'KafkaCryptoMessage', 'KafkaCrypto', 'KafkaCryptoStore', 'KafkaCryptoController', 'KafkaCryptoChainServer'])

