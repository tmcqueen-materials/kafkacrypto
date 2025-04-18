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

## Post Quantum Secure Cryptography

### Prerequisites

Use requires installing [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) with the sntrup761, ML-KEM-1024, and SPINCS+-SHAKE-128f-simple algorithms enabled (the default).

This in turn bumps the minimum python version required to 3.7.

For raspberry pis and other devices not officially supported by liqoqs, the following may help:
```
sudo apt-get install cmake ninja-build git
sudo pip3 install pytest pytest-xdist pyyaml
mkdir oqs
cd oqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs
git checkout 0.11.0 # can use as old as 0.8.0 for full support, or 0.7.2 for ephemeral PQ key exchange (but not signing)
# Only needed if PQ signing support is desired
# kat.json may fail to patch for <0.11.0, but can be ignored (except tests will fail)
curl https://raw.githubusercontent.com/tmcqueen-materials/kafkacrypto/refs/heads/master/liboqs-sphincs+-slhdsa.patch > liboqs-sphincs+-slhdsa.patch
patch -p1 < liboqs-sphincs+-slhdsa.patch
mkdir build
cd build
# Some variables will be unused depending on liboqs version; that is OK
cmake -G"Ninja" .. -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_USE_OPENSSL=OFF -DOQS_ENABLE_KEM_NTRUPRIME=ON -DOQS_ENABLE_KEM_ntruprime_sntrup761=ON -DOQS_ENABLE_KEM_ntruprime_ntrulpr653=OFF -DOQS_ENABLE_KEM_ntruprime_ntrulpr761=OFF -DOQS_ENABLE_KEM_ntruprime_ntrulpr857=OFF -DOQS_ENABLE_KEM_ntruprime_ntrulpr1277=OFF -DOQS_ENABLE_KEM_ntruprime_sntrup653=OFF -DOQS_ENABLE_KEM_ntruprime_sntrup857=OFF -DOQS_ENABLE_KEM_ntruprime_sntrup1277=OFF -DOQS_ENABLE_KEM_KYBER=OFF -DOQS_ENABLE_KEM_BIKE=OFF -DOQS_ENABLE_KEM_FRODOKEM=OFF -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF -DOQS_ENABLE_KEM_HQC=OFF -DOQS_ENABLE_SIG_DILITHIUM=OFF -DOQS_ENABLE_SIG_FALCON=OFF -DOQS_ENABLE_SIG_SPHINCS=ON -DOQS_ENABLE_SIG_sphincs_shake_128f_simple=ON -DOQS_ENABLE_SIG_sphincs_shake_128s_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake_192f_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake_192s_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake_256f_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake_256s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_128f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_128s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_192f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_192s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_256f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha2_256s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_128f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_128s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_192f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_192s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_256f_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_256s_simple=OFF -DOQS_ENABLE_SIG_sphincs_sha256_128f_robust=OFF -DOQS_ENABLE_SIG_sphincs_sha256_128s_robust=OFF -DOQS_ENABLE_SIG_sphincs_sha256_192f_robust=OFF -DOQS_ENABLE_SIG_sphincs_sha256_192s_robust=OFF -DOQS_ENABLE_SIG_sphincs_sha256_256f_robust=OFF -DOQS_ENABLE_SIG_sphincs_sha256_256s_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_128f_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_128s_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_192f_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_192s_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_256f_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_256s_robust=OFF -DOQS_ENABLE_SIG_sphincs_haraka_128f_simple=OFF -DOQS_ENABLE_SIG_sphincs_haraka_128s_simple=OFF -DOQS_ENABLE_SIG_sphincs_haraka_192f_simple=OFF -DOQS_ENABLE_SIG_sphincs_haraka_192s_simple=OFF -DOQS_ENABLE_SIG_sphincs_haraka_256f_simple=OFF -DOQS_ENABLE_SIG_sphincs_haraka_256s_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_128f_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_128s_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_192f_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_192s_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_256f_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_256s_robust=OFF -DOQS_ENABLE_SIG_sphincs_shake256_128f_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_128s_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_192f_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_192s_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_256f_simple=OFF -DOQS_ENABLE_SIG_sphincs_shake256_256s_simple=OFF -DOQS_ENABLE_SIG_PICNIC=OFF -DOQS_ENABLE_KEM_NTRU=OFF -DOQS_ENABLE_KEM_SABER=OFF -DOQS_ENABLE_SIG_RAINBOW=OFF -DOQS_ENABLE_KEM_ML_KEM=ON -DOQS_ENABLE_KEM_ml_kem_1024=ON -DOQS_ENABLE_KEM_ml_kem_768=OFF -DOQS_ENABLE_KEM_ml_kem_512=OFF -DOQS_ENABLE_SIG_ML_DSA=OFF -DOQS_ENABLE_SIG_MAYO=OFF -DOQS_ENABLE_SIG_CROSS=OFF -DOQS_ENABLE_SIG_UOV=OFF -DOQS_ENABLE_SIG_STFL_XMSS=OFF -DOQS_ENABLE_SIG_STFL_LMS=OFF
ninja
ninja run_tests
sudo ninja install
cd ../../liboqs-python
git checkout 0.10.0 # can use as old as 0.7.2
sudo pip3 install .
# the below may or may not be needed, depending on raspi os version
sudo ldconfig
```

### Key Exchange

Starting with version v0.9.10.0, kafkacrypto supports key exchange using Curve25519+sntrup761, a hybrid classical-pq key exchange algorithm. This mirrors support for the same hybrid added in OpenSSH 8.5.

Starting with version v0.9.11.0, kafkacrypto supports key exchange using Curve25519+ML-KEM-1024, a hybrid classical-pq key exchange algorithm, including the FIPS-standardized ML-KEM.

Starting with version v0.9.11.1dev0, kafkacrypto enables Curve25519, Curve25519+sntrup761, and Curve25519+ML-KEM-1024 by default for new CryptoKeys.

The script `enable-pq-exchange.py` assists in enabing pq key exchange. It must be enabled on both consumers and producers. Optionally, it can be used to select only a pq hybrid algorithm (see code documentation).

### Signing Keys

Starting with version v0.9.11.0, kafkacrypto supports key signing using Ed25519+SLH-DSA-SHAKE-128f, a hybrid classical-pq signing algorithm, including the FIPS-standardized SLH-DSA.

To enable pq signing, simply select a pq signing key when provisioning. Note that provisioning can be run multiple times for a single node to create keys of multiple types. Adding the line `keytypes : 4` just under the cryptokey line in `my-node-ID.config` can be used to enable only hybrid pq signing.

Note that to use password-based deterministic key provisioners, you also need to install [pyspx-slhdsa](https://github.com/tmcqueen-materials/pyspx-slhdsa). We hope to remove this dependency once liboqs-python exposes seed-based key generation.

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

## Version Compatibility
kafkacrypto is compatible with all versions of Python 3.3+, and can utilize both [kafka-python](https://github.com/dpkp/kafka-python) and [confluent-kafka](https://github.com/confluentinc/confluent-kafka-python) backends. It will automatically use one of these if already installed (preferring the higher performance confluent-kafka one).

For Python 3.12, kafka-python must be 2.0.3 or later; this dependency has not been released on PyPi, So you either need to use confluent-kafka, or install kafka-python directly from their github.

