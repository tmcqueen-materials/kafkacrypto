from kafka import KafkaConsumer as Consumer, KafkaProducer as Producer, TopicPartition
from collections import namedtuple

TopicPartitionOffset = namedtuple("TopicPartitionOffset",
  ["topic", "partition", "offset"])

class KafkaConsumer(Consumer):
  def assign_and_seek(self, partoffs):
    tps = []
    for tpo in partoffs:
      tps.append(TopicPartition(tpo.topic,tpo.partition))
    super().assign(tps)
    for tpo in partoffs:
      if (tpo.offset > 0):
        super().seek(TopicPartition(tpo.topic,tpo.partition),tpo.offset)

class KafkaProducer(Producer):
  def poll(self, timeout=0):
    pass
