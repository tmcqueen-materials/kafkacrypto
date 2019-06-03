# kafkacrypto
Message Layer Encryption for Kafka

Available on PyPI at https://pypi.org/project/kafkacrypto/  
Available on Github at https://github.com/tmcqueen-materials/kafkacrypto

## Quick Start
On every kafka consumer or producer node, do:
  1. `pip3 install kafkacrypto`
  1. [Download](https://github.com/tmcqueen-materials/kafkacrypto/raw/master/tools/simple-provision.py) `simple-provision.py`
  1. Run: `./simple-provision.py` and follow the instructions. Use the same root of trust password on all nodes.

In your producer/consumer code:
```python
from kafkacrypto import KafkaCrypto
nodeId = 'my-node-ID'

# setup separate consumer/producers for the crypto key passing messages. DO NOT use these for
# other messages.
kcc = KafkaConsumer(...your server params...)
kcp = KafkaProducer(...your server params...)
kc = KafkaCrypto(nodeId,kcp,kcc)

... Your code here ...

# Here is how you configure your producer/consumer objects to use the crypto (de)serializers
producer = KafkaProducer(...,key_serializer=kc.getKeySerializer(), value_serializer=kc.getValueSerializer())
consumer = KafkaConsumer(...,key_deserializer=kc.getKeyDeserializer(), value_deserializer=kc.getValueDeserializer())

... Your code here ...
```

And that's it! Your producers and consumers should function as normal, but all traffic within Kafka is encrypted. 

If automatic topic creation is disabled, then one more action is needed. For each "root topic" you must create the requisite key-passing topics. By default these are `root.reqs` and `root.keys`, where root is replaced with the root topic name. It is safe to enable regular log compaction on these topics.

## Root Topics
kafkacrypto uses unique keys on a per-"root topic" basis. A root topic is defined as the topic name before the first user-defined separator. The default separator is "`.`". Thus all of these:  
`example001`  
`example001.foo.bar.baz`  
`example001.foo.bar`  
`example001.foo`  
have the same root topic of `example001`, whereas `example001_baz.bar.foo` has the root topic `example001_baz`. Since kafka does not recommend using both "`.`" and "`_`" in topic names, if you wish every topic to use a unique set of keys, use "`_`" (and not "`.`") in names, or change the defined topic separator.

## Undecryptable Messages
kafkacrypto is designed so that messages being sent can **always** be encrypted once a KafkaCrypto object is successfully created. However, it is possible for a consumer to receive a message for which it does not have a decryption key, i.e. an undecryptable message. This is most often because the asynchronous key exchange process has not completed before the message is received, or because the consumer is not authorized to receive on that topic. 

To handle this scenario, all deserialized messages are returned as [KafkaCryptoMessage](https://github.com/tmcqueen-materials/kafkacrypto/blob/master/kafkacrypto/message.py) objects. The `.isCleartext()` method can be used to determine whether the message component was successfully decrypted or not:
```python
# consumer is setup with KafkaCrypto deserializers as shown above
# 'key' refers to the key of key->value pairs from Kafka, not a cryptographic key
for msg in consumer:
  if (msg.key.isCleartext()):
    # message key was decrypted. bytes(msg.key) is the decrypted message key
  else:
    # message key was not decrypted. bytes(msg.key) is the raw (undecrypted) message key
    # msg.key can be discarded, or saved and decryption attempted at a later time
    # by doing KafkaCrypto.getKeyDeserializer().deserialize(msg.topic, msg.key)
  if (msg.value.isCleartext()):
    # message value was decrypted. bytes(msg.value) is the decrypted message value
  else:
    # message value was not decrypted. bytes(msg.value) is the raw (undecrypted) message value
    # msg.value can be discarded, or saved and decryption attempted at a later time
    # by doing KafkaCrypto.getValueDeserializer().deserialize(msg.topic, msg.value)
```
The convenience method `.getMessage()` can be used instead to return the message as bytes if successfully decrypted, or to raise a `KafkaCryptoMessageError` if decryption failed.

## Stacking (De)Serializers
Although not recommended, it is possible to combine multiple (De)Serializers in a single chain to, e.g., encrypt/decrypt and JSON encode/decode a message. Such an example is here:
```python
class CompoundDeSes(kafka.serializer.Serializer,kafka.serializer.Deserializer):
  def __init__(self, *args):
    self._ser = list(args)
  def serialize(self, topic, keyvalue):
    for ser in self._ser:
      if (isinstance(ser, (kafka.serializer.Serializer,)):
        keyvalue = ser.serialize(topic,keyvalue)
      else:
        keyvalue = ser(keyvalue)
    return keyvalue
  def deserialize(self, topic, keyvalue):
    for ser in self._ser:
      if (isinstance(ser, (kafka.serializer.Deserializer,)):
        keyvalue = ser.deserialize(topic,keyvalue)
      else:
        keyvalue = ser(keyvalue)
    return keyvalue

...

# Stacked (De)Serializers. Usually, you will encrypt last on serialization, and decrypt
# first on deserialization. Do not forget that exceptions are likely as undecryptable
# messages appear.
producer = KafkaProducer(...,key_serializer=CompoundDeSes(json.dumps,kc.getKeySerializer()), value_serializer=CompoundDeSes(json.dumps,kc.getValueSerializer()))
consumer = KafkaConsumer(...,key_deserializer=CompoundDeSes(kc.getKeyDeserializer(),json.loads), value_deserializer=CompoundDeSes(kc.getValueDeserializer(),json.loads))
```

## Troubleshooting
If something is not working, enable logging to get detailed information:
```python
import logging

logging.basicConfig(level=logging.WARNING)
logging.getLogger("kafkacrypto").setLevel(level=logging.INFO) # set to logging.DEBUG for more verbosity
```

## Advanced Usage
kafkacrypto has been designed to seamlessly support a range of key exchange authorization and delegation mechanisms beyond the simple single-password root of trust. An example of a simple "controller-based" intermediary is included in the main package. The requisite controller can be setup as:
```python
#!/usr/bin/python3
from kafka import KafkaConsumer, KafkaProducer
from kafkacrypto import KafkaCryptoController

nodeId = 'controller-name'

# use your normal server parameters in place of the ...
kcc = KafkaConsumer(..., enable_auto_commit=False, group_id=nodeId)
kcp = KafkaProducer(...)
controller = KafkaCryptoController(nodeId,kcp,kcc)
controller._mgmt_thread.join()
```
The configuration parameters inside the provision script should be adjusted so that the "subscribe" and "key request" suffixes are distinct (see comment in `simple-provision.py`, or use `provision.py` instead). If automatic topic creation is disabled, then the topic `root.subs` must also be created. It is safe to enable regular log compaction on this topic.

## Design, Specification, and Security Analysis
kafkacrypto is already in limited production use, and should be stable enough for broad adoption. However, a detailed security analysis of the kafkacrypto framework is still in progress, and use of this code should be considered experimental.
