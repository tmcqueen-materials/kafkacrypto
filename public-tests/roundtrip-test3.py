#!/usr/bin/env python3

from threading import Thread
from kafkacrypto import KafkaCryptoStore, KafkaCrypto, KafkaConsumer, KafkaProducer, KafkaCryptoController
from time import sleep,time
from pysodium import randombytes

class ControllerThread(object):
  def __init__(self,joinon=None):
    self._joinon = joinon
    self.kcs = KafkaCryptoStore("node4.config")
    self._my_thread = Thread(target=self._my_thread_proc)
    self._my_thread.start()

  def _my_thread_proc(self):
    # Setup KafkaCrypto
    self.kcc = KafkaConsumer(**self.kcs.get_kafka_config('consumer',extra='crypto'))
    self.kcp = KafkaProducer(**self.kcs.get_kafka_config('producer',extra='crypto'))
    controller = KafkaCryptoController(None,self.kcp,self.kcc,config=self.kcs)
    # controller._mgmt_thread.join()
    if not (self._joinon is None):
      self._joinon.join()
    self.kcc.close()
    self.kcp.close()
    self.kcs.close()

class ProdThread(object):
  def __init__(self,uval,kcs,joinon=None):
    self._uval = uval
    self._joinon = joinon
    self.kcs = kcs
    self._my_thread = Thread(target=self._my_thread_proc)
    self._my_thread.start()

  def _my_thread_proc(self):
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
    # we are last user, so close
    self.kcs.close()

class ConsumeThread(object):
  def __init__(self,uval):
    self._uval = uval
    self.kcs = KafkaCryptoStore("node5.config")
    self._my_thread = Thread(target=self._my_thread_proc)
    self._my_thread.start()

  def _my_thread_proc(self):
    # Setup KafkaCrypto
    self.kcc = KafkaConsumer(**self.kcs.get_kafka_config('consumer',extra='crypto'))
    self.kcp = KafkaProducer(**self.kcs.get_kafka_config('producer',extra='crypto'))
    self.kc = KafkaCrypto(None,self.kcp,self.kcc,config=self.kcs)
    kafka_config = self.kcs.get_kafka_config('consumer')
    kafka_config['key_deserializer'] = self.kc.getKeyDeserializer()
    kafka_config['value_deserializer'] = self.kc.getValueDeserializer()
    self.consumer = KafkaConsumer(**kafka_config)
    self.consumer.subscribe(["openmsitest.0"])
    end_time = time()+60
    rcvd = False
    while not rcvd and time() < end_time:
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
    # need to close kcs after done being used by ProdThread
    if not rcvd:
      raise RuntimeError("Value Not Received!")

for i in range(0,3):
  uval = randombytes(64)
  t2 = ConsumeThread(uval)
  t3 = ControllerThread(t2._my_thread)
  t1 = ProdThread(uval,t2.kcs,t2._my_thread)
  t1._my_thread.join(60+5)

