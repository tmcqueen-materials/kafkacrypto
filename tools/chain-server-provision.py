#!/usr/bin/python3 -i
# Note: interactive needed to avoid input prematurely truncating the input (TODO: write our own readline that does not suffer from this limitation)
# TODO: Adjust to fully support multiple signing chains.
from pysodium import randombytes
import msgpack
from configparser import ConfigParser
from time import time
from getpass import getpass
from os import path
from binascii import unhexlify, hexlify
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.chain import process_chain
from kafkacrypto.provisioners import PasswordProvisioner
from kafkacrypto.cryptokey import CryptoKey
from kafkacrypto.utils import msgpack_default_pack
from kafkacrypto.keys import KEMPublicKey
from kafkacrypto import KafkaCryptoStore

#
# Need to ask for keytype to load appropriate global configuration
#
keytype = 0
while not (keytype in [1,4]):
  try:
    keytype = int(input('Key type (1 = Ed25519 (default), 4 = Ed25519+SLH-DSA-SHAKE-128f)? '))
  except ValueError:
    keytype = 1

#
# Global configuration
#

lifetime = 31622400 # chain server default lifetime (1 years)

if keytype == 1:
  # Ed25519
  _ss0_escrow = KEMPublicKey(unhexlify(b'escrow-key-here'))
  _rot = unhexlify(b'rot-here')
  _msgrot = msgpack.packb([0,b'\x90',_rot], default=msgpack_default_pack, use_bin_type=True)
elif keytype == 4:
  # Ed25519+SLH-DSA-SHAKE-128f keys (25519+ML-KEM-1024 escrow)
  _ss0_escrow = KEMPublicKey(unhexlify(b'escrow-key-here'))
  _rot = unhexlify(b'rot-here')
  _msgrot = msgpack.packb([0,b'\x90',_rot], default=msgpack_default_pack, use_bin_type=True)
else:
  assert False, "Invalid Keytype"

# Common configs
_usages = {      'chain-server': ['key-encrypt','key-encrypt-subscribe'],
                 }

print('Beginning provisioning process. This should be run on the chain server device being provisioned.')
nodeID = ''
while len(nodeID) < 1:
  nodeID = input('Node ID: ')
key = 'chain-server'

topics = None
while topics is None:
  topic = input('Enter a space separated list of topics this ' + key + ' will use: ')
  topics = list(set(map(lambda i: i.split('.',1)[0], topic.split())))
  if (len(topics) < 1):
    ans = input('Are you sure you want to allow all topics (y/N)?')
    if (len(ans) == 0 or ans[0].lower() != 'y'):
      topics = None
    else:
      topics = ['^.*$']

pathlen=2
pathlen = input('Enter a maximum pathlength (-1 for no limit; default ' + str(pathlen) + '):')
if len(pathlen)<1:
  pathlen=2
else:
  pathlen=int(pathlen)

lt = input('Enter a maximum lifetime in seconds (-1 for no limit; default ' + str(lifetime) + '):')
if len(lt)>0:
  lifetime = int(lt)

print('Root topics will be:')
print(topics)
if lifetime!=-1:
  print('Lifetime of initial crypto configuration will be', lifetime/86400, 'days.')
else:
  print('No maximum lifetime')
if pathlen!=-1:
  print('Maximum pathlength is', pathlen)
else:
  print('No maximum pathlength')
print('')

ans = ''
while len(ans) < 1 or (ans[0].lower() != 'n' and ans[0].lower() != 'y'):
  ans = input('Are you sure all the information above is correct (yes/no)? ')

assert (ans[0].lower() == 'y'), 'Aborting per user request.'

# Generate identify keypair and chain, and write cryptokey config file
# TODO: this assumes there is only one key of each type, which should be true, but...
eck = CryptoKey(nodeID + ".crypto", keytypes=[keytype])
for idx in range(0,eck.get_num_spk()):
  if eck.get_spk(idx).same_type(keytype):
    break
pk = eck.get_spk(idx)

poison = [['usages',_usages[key]]]
if len(topics) > 0:
  poison.append(['topics',topics])
if pathlen != -1:
  poison.append(['pathlen',pathlen])
poison = msgpack.packb(poison, use_bin_type=True)
msg = [time()+lifetime if lifetime!=-1 else 0, poison, pk]
print('New Chain Server', '(', hexlify(bytes(pk)), '):', hexlify(msgpack.packb(msg, default=msgpack_default_pack, use_bin_type=True)))
msg = unhexlify(input('ROT Signed Value (hex):'))
chain = msgpack.packb([msg], default=msgpack_default_pack, use_bin_type=True)
pk2 = process_chain(chain,None,None,allowlist=[_msgrot])[0]
assert len(pk2) >= 3, "Malformed ROT Signed Value"
print(nodeID, 'public key:', hexlify(bytes(pk)))

# Next, write config
kcs = KafkaCryptoStore(nodeID + ".config", nodeID)
kcs.store_value('chain'+str(idx), chain, section='chains')
if kcs.load_value('cryptokey') is None:
  kcs.store_value('cryptokey', "file#" + nodeID + ".crypto")
kcs.store_value('rot'+str(idx), _msgrot, section='allowlist')
if kcs.load_value('temporary', section='allowlist'):
  print("Found temporary ROT, removing.")
  kcs.store_value('temporary', None, section='allowlist')
kcs.store_value("test", "test", section="chainkeys")
kcs.store_value("test", None, section="chainkeys")

print('Congratulations! Chain server provisioning is complete.')
