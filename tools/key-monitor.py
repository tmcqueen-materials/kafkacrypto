#!/usr/bin/python3
import msgpack
import logging
import base64
import pysodium
from sys import argv, exit
from time import time, sleep
from kafkacrypto import KafkaCryptoStore, KafkaConsumer
from kafkacrypto.keys import get_pks
from kafkacrypto.chain import process_chain, printable_cert
from kafkacrypto.utils import format_exception_shim

# Process configuration file
if len(argv) != 2:
  exit('Invalid command line. Usage: key-monitor.py file.config')
kcs = KafkaCryptoStore(argv[1])

# No need to setup kafkacrypto since we are not decrypting messages

# read key-monitor specific values
refresh_secs = kcs.load_value('refresh_secs', default=300)
restart_commit_beginning = kcs.load_value('restart_commit_beginning',default=False)
restart_commit_beginning_wait = kcs.load_value('restart_commit_beginning_wait',default=5)
poll_timeout_ms = kcs.load_value('poll_timeout_ms', default=1000)
topics_pattern = '(^.*\.reqs$)|(^.*\.subs$)|(^.*\.keys$)'

# read needed general configs
allowlist = kcs.load_section('allowlist',defaults=False)
if not (allowlist is None):
  allowlist = allowlist.values()

## End read configuration

kafka_config = kcs.get_kafka_config('consumer')
consumer = KafkaConsumer(**kafka_config)
consume_refresh_ts = time()+refresh_secs
consumer.subscribe(pattern=topics_pattern)
if restart_commit_beginning:
  logging.warning("Restarting reading from beginning of topics.")
  # need to poll a few times to make sure all topics are actually subscribed
  for i in range(0,restart_commit_beginning_wait):
    rv = consumer.poll(timeout_ms=5000)
    sleep(5)
  consumer.seek_to_beginning()
  logging.warning("Finished seeking to beginning.")

while True:
  if (time() > consume_refresh_ts):
    consume_refresh_ts = time()+refresh_secs
    consumer.subscribe(pattern=topics_pattern)
  rv = consumer.poll(timeout_ms=poll_timeout_ms)
  for tp,msgs in rv.items():
    for msg in msgs:
      chain = msg.value
      try:
        pcr = process_chain(chain, allowlist=allowlist, checktime=lambda: msg.timestamp/1000 if msg.timestamp is not None else time()) # timestamp is in ms
        print(tp.topic + ":", pcr[1])
      except Exception as e:
        # without a ROT, we don't know if our first entry is version 1 or version 4.
        # So try version 1, and if it fails, try version 4 (version 4 cannot have legacy encoding)
        toprint = []
        try:
          chain = msgpack.unpackb(chain,raw=False)
          legacy = False
        except:
          chain = msgpack.unpackb(chain,raw=True)
          legacy = True
        try:
          pk = msgpack.unpackb(chain[0][pysodium.crypto_sign_BYTES:], raw=legacy)
        except:
          try:
            pk = msgpack.unpackb(chain[0][pysodium.crypto_sign_BYTES:], raw=not legacy)
            legacy = not legacy
          except:
            pk = msgpack.unpackb(chain[0][17088+pysodium.crypto_sign_BYTES:], raw=False)
            legacy = False
        pk[2] = get_pks(pk[2])
        toprint.append(printable_cert(pk))
        chain = chain[1:]
        for npk in chain:
          if pk[2].version == 1:
            pk = msgpack.unpackb(npk[pysodium.crypto_sign_BYTES:], raw=legacy)
          else: # version = 4
            pk = msgpack.unpackb(npk[17088+pysodium.crypto_sign_BYTES:], raw=legacy)
          pk[2] = get_pks(pk[2])
          toprint.append(printable_cert(pk))
        print(tp.topic + " (INVALID):", toprint)
        print("      WHY:", format_exception_shim(e))
