#!/usr/bin/env python3
from threading import Thread
from kafkacrypto import KafkaCryptoStore, KafkaCrypto, KafkaConsumer, KafkaProducer
from time import sleep
from pysodium import randombytes

class ProdThread(object):
  def __init__(self,uval,joinon=None):
    self._uval = uval
    self._joinon = joinon
    self._my_thread = Thread(target=self._my_thread_proc)
    self._my_thread.start()

  def _my_thread_proc(self):
    self.kcs = KafkaCryptoStore("node1.config")
    # Setup KafkaCrypto
    self.kcc = KafkaConsumer(**self.kcs.get_kafka_config('consumer',extra='crypto'))
    self.kcp = KafkaProducer(**self.kcs.get_kafka_config('producer',extra='crypto'))
    self.kc = KafkaCrypto(None,self.kcp,self.kcc,config=self.kcs)
    kafka_config = self.kcs.get_kafka_config('producer')
    kafka_config['key_serializer'] = self.kc.getKeySerializer()
    kafka_config['value_serializer'] = self.kc.getValueSerializer()
    self.producer = KafkaProducer(**kafka_config)
    sleep(5)
    self.producer.send("openmsitest.0",value=self._uval)
    self.producer.poll(1)
    sleep(5)
    self.producer.poll(1)
    if not (self._joinon is None):
      self._joinon.join()
    self.producer.close()
    self.kcc.close()
    self.kcp.close()
    self.kc.close()

class ConsumeThread(object):
  def __init__(self,uval):
    self._uval = uval
    self._my_thread = Thread(target=self._my_thread_proc)
    self._my_thread.start()

  def _my_thread_proc(self):
    self.kcs = KafkaCryptoStore("node2.config")
    # Setup KafkaCrypto
    self.kcc = KafkaConsumer(**self.kcs.get_kafka_config('consumer',extra='crypto'))
    self.kcp = KafkaProducer(**self.kcs.get_kafka_config('producer',extra='crypto'))
    self.kc = KafkaCrypto(None,self.kcp,self.kcc,config=self.kcs)
    kafka_config = self.kcs.get_kafka_config('consumer')
    kafka_config['key_deserializer'] = self.kc.getKeyDeserializer()
    kafka_config['value_deserializer'] = self.kc.getValueDeserializer()
    self.consumer = KafkaConsumer(**kafka_config)
    self.consumer.subscribe(["openmsitest.0"])
    cnt = 0
    rcvd = False
    while not rcvd and cnt < 65:
      rv = self.consumer.poll(timeout_ms=1000)
      for tp,msgs in rv.items():
        for msg in msgs:
          if bytes(msg.value) == self._uval:
            print("Message Successfully Received!")
            rcvd = True
    self.consumer.close()
    self.kcc.close()
    self.kcp.close()
    self.kc.close()
    if not rcvd:
      raise RuntimeError("Value Not Received!")

for i in range(0,3):
  uval = randombytes(64)
  t2 = ConsumeThread(uval)
  t1 = ProdThread(uval,t2._my_thread)
  t1._my_thread.join(65)

