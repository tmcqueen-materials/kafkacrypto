# Public Tests
Public tests for Message Layer Encryption for Kafka

## Usage

### roundtrip-test1
This test carries out three successive full round-trips of encrypted data with a live broker. It execises many
components of KafakCrypto, including configuration file handling, open and close operations, etc. Relies on
group timeout not being "too long", since confluent-kafka-python does not gracefully support close operations
on all platforms.

  1. Install kafkacrypto
  1. Use tools/simple-provision.py to generate two configs: node1 (producer) and node2 (consumer).
  1. Adjust node1.config and node2.config to point to live broker.
  1. If desired, set `log_level : 20` in config.
  1. Make sure broker allows autocreation of topics, or create the topics `openmsitest.0`, `openmsitest.subs`, `openmsitest.reqs`, `openmsitest.keys`
  1. Run: `./roundtrip-test1.py`

### roundtrip-test2
This test carries out three successive full round-trips of encrypted data with a live broker. It execises many
components of KafakCrypto, including configuration file handling, open and close operations, etc. Relies on
group timeout not being "too long", since confluent-kafka-python does not gracefully support close operations
on all platforms. This variant uses a single config file for both ends (not recommended in production, but
invaluable in unit tests).

  1. Install kafkacrypto
  1. Use tools/simple-provision.py to generate one config: node3 (producer and consumer).
  1. Adjust node3.config to point to live broker.
  1. If desired, set `log_level : 20` in config.
  1. Make sure broker allows autocreation of topics, or create the topics `openmsitest.0`, `openmsitest.subs`, `openmsitest.reqs`, `openmsitest.keys`
  1. Run: `./roundtrip-test2.py`

### roundtrip-test3
This test carries out three successive full round-trips of encrypted data with a live broker. It execises many
components of KafakCrypto, including configuration file handling, open and close operations, etc. Relies on
group timeout not being "too long", since confluent-kafka-python does not gracefully support close operations
on all platforms. This variant uses a single config file for both ends that requires a controller to function
(so this test also runs an appropriate controller).

  1. Install kafkacrypto
  1. Use tools/simple-provision.py to generate two configs: node4 (controller), node5 (producer and consumer, only function with controller).
  1. Adjust node4.config and node5.config to point to live broker.
  1. If desired, set `log_level : 20` in config.
  1. Make sure broker allows autocreation of topics, or create the topics `openmsitest.0`, `openmsitest.subs`, `openmsitest.reqs`, `openmsitest.keys`
  1. Run: `./roundtrip-test3.py`

