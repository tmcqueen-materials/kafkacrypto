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

## Design, Specification, and Security Analysis
kafkacrypto is already in limited production use, and should be stable enough for broad adoption. However, a detailed security analysis of the kafkacrypto framework is still in progress, and use of this code should be considered experimental.
