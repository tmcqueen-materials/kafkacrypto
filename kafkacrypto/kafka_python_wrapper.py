from kafka import KafkaConsumer as Consumer, KafkaProducer as Producer, TopicPartition, OffsetAndMetadata
from collections import namedtuple

TopicPartitionOffset = namedtuple("TopicPartitionOffset",
  ["topic", "partition", "offset"])

OFFSET_BEGINNING = -2
OFFSET_END = -1

class KafkaConsumer(Consumer):
  def assign_and_seek(self, partoffs):
    tps = []
    for tpo in partoffs:
      tps.append(TopicPartition(tpo.topic,tpo.partition))
    super().assign(tps)
    for tpo in partoffs:
      if (tpo.offset > 0):
        super().seek(TopicPartition(tpo.topic,tpo.partition),tpo.offset)
      elif (tpo.offset == OFFSET_BEGINNING):
        super().seek_to_beginning([TopicPartition(tpo.topic,tpo.partition)])
      elif (tpo.offset == OFFSET_END):
        super().seek_to_end([TopicPartition(tpo.topic,tpo.partition)])
  def subscribe(self, topics=[], pattern=None, listener=None):
    if len(topics)>0 and pattern!=None:
      # kafka-python only allows regex or topics, but not both. So
      # we convert topics into regexes
      if not (pattern.startswith('(') and pattern.endswith(')')):
        pattern = '(' + pattern + ')'
      for nt in topics:
        ntr = nt
        for chr in ['.','^','$','*','+','?','{','}','[',']','\\','|','(',')']:
          ntr = ntr.replace(chr,'\\' + chr)
        pattern += '|(^' + ntr + '$)'
      super().subscribe(pattern=pattern,listener=listener)
    else:
      super().subscribe(topics=topics,pattern=pattern,listener=listener)

class KafkaProducer(Producer):
  def poll(self, timeout=0):
    pass
  def flush(self, timeout=None, timeout_jiffy=None):
    return super().flush(timeout=timeout)
