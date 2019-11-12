# kafkacrypto
Message Layer Encryption for Kafka

Available on PyPI at https://pypi.org/project/kafkacrypto/  
Available on Github at https://github.com/tmcqueen-materials/kafkacrypto  
Java implementation available on Github at https://github.com/tmcqueen-materials/kafkacrypto-java

## Quick Start
On every kafka consumer or producer node, do:
  1. `pip3 install kafkacrypto`
  1. [Download](https://github.com/tmcqueen-materials/kafkacrypto/raw/master/tools/simple-provision.py) `simple-provision.py`
  1. Run: `./simple-provision.py` and follow the instructions. Use the same root of trust password on all nodes.

In your producer/consumer code:
```python
from kafkacrypto import KafkaCrypto, KafkaConsumer, KafkaProducer
nodeId = 'my-node-ID'

# setup separate consumer/producers for the crypto key passing messages. DO NOT use these for
# other messages.
kcc = KafkaConsumer(...your server params in kafka-python form...)
kcp = KafkaProducer(...your server params in kafka-python form...)
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

## Universal Configuration File
kafkacrypto separates the storage of cryptographic secrets and non-secret configuration information:
  1. `my-node-ID.config`: Non-secret parameters, in Python ConfigParser format.
  1. `my-node-ID.seed`: Next ratchet seed, when using default implementation of Ratchet. Key secret, should never be saved or transmitted plaintext.
  1. `my-node-ID.crypto`: Identification private key, when using default implementation of Cryptokey. Key secret, should never be saved or transmitted plaintext.

Alternative implementations of Ratchet and Cryptokey enable secrets to be managed by specialized hardware (e.g. HSMs).

It is also possible to use `my-node-ID.config` to manage all configuration directives, including those that control Kafka. A sample implementation, which reads the node ID from `node_id` in the `DEFAULT` section is:
```python
#!/usr/bin/python3
from sys import argv
from kafkacrypto import KafkaCrypto, KafkaCryptoStore, KafkaConsumer, KafkaProducer

# Process configuration file
if len(argv) != 2:
  exit('Invalid command line.')
kcs = KafkaCryptoStore(argv[1])

# Setup KafkaCrypto
kcc = KafkaConsumer(**kcs.get_kafka_config('consumer',extra='crypto'))
kcp = KafkaProducer(**kcs.get_kafka_config('producer',extra='crypto'))
kc = KafkaCrypto(None,kcp,kcc,config=kcs)

# read program specific values
value1 = kcs.load_value('value1')
value2 = kcs.load_value('value2')

## End read configuration

# Setup Kafka Consumer and Producer
kafka_config = kcs.get_kafka_config('consumer')
kafka_config['key_deserializer'] = kc.getKeyDeserializer()
kafka_config['value_deserializer'] = kc.getValueDeserializer()
consumer = KafkaConsumer(**kafka_config)
kafka_config = kcs.get_kafka_config('producer')
kafka_config['key_serializer'] = kc.getKeySerializer()
kafka_config['value_serializer'] = kc.getValueSerializer()
producer = KafkaProducer(**kafka_config)


... your code here ...

# Save new values
kcs.store_value('value1', 'value-of-value1')
kcs.store_value('value2', 'value-of-value2')
```

## Kafka Python Interfaces
kafkacrypto has been extensively tested with kafka-python. It will use confluent_kafka if available via a thin compatibility wrapper. Other wrappers can be added (submit a pull request!)

## Advanced Usage
kafkacrypto has been designed to seamlessly support a range of key exchange authorization and delegation mechanisms beyond the simple single-password root of trust. An example of a simple "controller-based" intermediary is included in the main package. The requisite controller can be setup as:
```python
#!/usr/bin/python3
from kafkacrypto import KafkaCryptoController, KafkaConsumer, KafkaProducer

nodeId = 'controller-name'

# use your normal server parameters in place of the ...
kcc = KafkaConsumer(..., enable_auto_commit=False, group_id=nodeId)
kcp = KafkaProducer(...)
controller = KafkaCryptoController(nodeId,kcp,kcc)
controller._mgmt_thread.join()
```
The configuration parameters inside the provision script should be adjusted so that the "subscribe" and "key request" suffixes are distinct (see comment in `simple-provision.py`, or use `provision.py` instead). If automatic topic creation is disabled, then the topic `root.subs` must also be created. It is safe to enable regular log compaction on this topic.

Another common desire is to use very short chain lifetimes. Chains can be refreshed automatically and pushed to users. The requisite ChainServer can be setup as:
```python
#!/usr/bin/python3
from kafkacrypto import KafkaCryptoChainServer

nodeId = 'chain-server-name'

chainserver = KafkaCryptoChainServer(nodeId)
chainserver._mgmt_thread.join()
```
The sample provision script can appropriately setup keys for the ChainServer as well.

## Design, Specification, and Security Analysis
kafkacrypto is already in limited production use, and should be stable enough for broad adoption. However, a detailed security analysis of the kafkacrypto framework is still in progress, and use of this code should be considered experimental.

## Security Contact

Potential security issues can be reported to <securty@kafkacrypto.org>. Encryption is not required, but if you want to encrypt the email you can use the following PGP key.
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
NZ1gD4wDwSGlNMe+vuxj
=kElQ
-----END PGP PUBLIC KEY BLOCK-----
```

