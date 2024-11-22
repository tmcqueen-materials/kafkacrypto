#!/usr/bin/python3
# TODO: Adjust to fully support multiple signing chains
import pysodium
import msgpack
from os import path
from configparser import ConfigParser
from time import time
from getpass import getpass
from binascii import unhexlify, hexlify
from kafkacrypto.cryptokey import CryptoKey
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.chain import process_chain
from kafkacrypto.utils import str_encode, msgpack_default_pack
from kafkacrypto.provisioners import PasswordProvisioner, PasswordROT
from kafkacrypto import KafkaCryptoStore

#
# Global configuration
#

_lifetime = 316224000 # lifetime (10 years)
_usages = {  'producer': ['key-encrypt'],
             'consumer': ['key-encrypt-request','key-encrypt-subscribe'],
             'prodcon': ['key-encrypt','key-encrypt-request','key-encrypt-subscribe'],
             'prodcon-limited': ['key-encrypt','key-encrypt-subscribe'],
             'consumer-limited': ['key-encrypt-subscribe'],
             'controller': ['key-encrypt-request'],
             }
_keys = {    'producer': 'producer',
             'consumer': 'consumer',
             'prodcon': 'prodcon',
             'prodcon-limited': 'prodcon',
             'consumer-limited': 'consumer',
             'controller': 'consumer',
             }

# Get KeyType
keytype = 0
while not (keytype in [1,4]):
  try:
    kt = input('Key type (1 = Ed25519 (default), 4 = Ed25519+SLH-DSA-SHAKE-128f)? ')
    if len(kt) == 0:
      keytype = 1
    else:
      keytype = int(kt)
  except ValueError:
    pass

# Get ROT first
password = ''
while len(password) < 12:
  password = getpass('ROT Password (12+ chars): ')
rot = PasswordROT(password, keytype)

_rot = rot._pk
_msgrot = msgpack.packb([0,b'\x90',_rot], default=msgpack_default_pack, use_bin_type=True)
_chainrot = _rot
_msgchainrot = _msgrot

# Get Provisioning keys second
password = ''
while len(password) < 6:
  password = getpass('Provisioning Password (6+ chars): ')
prov = PasswordProvisioner(password, _rot, keytype)

# Generate signed chains
_signedprov = { 'producer': None,
            'consumer': None,
            'prodcon': None,
          }
for kn in _signedprov.keys():
  key=prov._pk[kn]
  poison = msgpack.packb([['usages',_usages[kn]]], default=msgpack_default_pack, use_bin_type=True)
  tosign = msgpack.packb([0,poison,key], default=msgpack_default_pack, use_bin_type=True)
  _signedprov[kn] = rot._sk.crypto_sign(tosign)

_msgchains = { 'producer': msgpack.packb([_signedprov[_keys['producer']]], use_bin_type=True),
               'consumer': msgpack.packb([_signedprov[_keys['consumer']]], use_bin_type=True),
               'prodcon': msgpack.packb([_signedprov[_keys['prodcon']]], use_bin_type=True),
               'prodcon-limited': msgpack.packb([_signedprov[_keys['prodcon-limited']]], use_bin_type=True),
               'consumer-limited': msgpack.packb([_signedprov[_keys['consumer-limited']]], use_bin_type=True),
               'controller': msgpack.packb([_signedprov[_keys['controller']]], use_bin_type=True),
             }

# Now do actual provisioning process
print('Beginning provisioning process. This should be run on the device being provisioned.')
nodeID = ''
while len(nodeID) < 1:
  nodeID = input('Node ID: ')
print('Is nodeID =', nodeID, 'a:')
print('1. Controller')
print('2. Producer')
print('3. Consumer')
print('4. Consumer and Producer')
choice = 0
while choice<1 or choice>4:
  try:
    choice = int(input('? '))
  except ValueError:
    pass

sole = False

if (choice == 3 or choice == 4):
  limited = ''
  limited = input('Limit the consumer to only functioning with controllers (y/N)? ')
  if len(limited)>0 and limited[0].lower() == 'y':
    limited = True
  else:
    limited = False

if (choice == 1):
  key = 'controller'
elif (choice == 2):
  key = 'producer'
elif (choice == 3 and limited):
  key = 'consumer-limited'
elif (choice ==	3 and not limited):
  key =	'consumer'
elif (choice == 4 and limited):
  key =	'prodcon-limited'
elif (choice ==	4 and not limited):
  key =	'prodcon'
else:
  assert False,'Invalid combination of choices!'

# Check we have appropriate chains
if (choice == 1):
  # Controllers must be signed by ROT
  _msgchkrot = _msgrot
else:
  # Everyone else by Chain ROT (may = ROT)
  _msgchkrot = _msgchainrot
assert (len(_msgchains[key]) > 0), 'A trusted chain for ' + key + ' is missing. This should not happen with simple-provision, please report as a bug.'
pk = process_chain(_msgchains[key],None,None,allowlist=[_msgchkrot])[0]
assert (len(pk) >= 3 and pk[2] == prov._pk[_keys[key]]), 'Malformed chain for ' + key + '. Did you enter your passwords correctly?'

topics = None
while topics is None:
  topic = input('Enter a space separated list of topics this ' + key + ' will use: ')
  topics = list(set(map(lambda i: i.split('.',1)[0], topic.split())))
  if (len(topics) < 1):
    ans = input('Are you sure you want to allow all topics (Y/n)?')
    if len(ans) > 0 and (ans[0].lower() == 'n'):
      topics = None
    else:
      topics = ['^.*$']

pathlen = ''
pathlen = input('Enter a maximum pathlength (-1 for no limit; default 1):')
if len(pathlen)<1:
  pathlen=1
else:
  pathlen=int(pathlen)

print('Root topics will be:')
print(topics)
print('Lifetime of initial crypto configuration will be', _lifetime/86400, 'days.')
if pathlen!=-1:
  print('Maximum pathlength is', pathlen)
else:
  print('No maximum pathlength')
print('')

ans = ''
while len(ans) < 1 or (ans[0].lower() != 'n' and ans[0].lower() != 'y'):
  ans = input('Are you sure all the information above is correct (yes/no)? ')

assert (ans[0].lower() == 'y'), 'Aborting per user request.'

# Generate KDF seed first, if needed
if path.exists(nodeID + ".seed"):
  with open(nodeID + ".seed", "rb+") as f:
    seedidx,rb = msgpack.unpackb(f.read(),raw=True)
    f.seek(0,0)
    f.write(msgpack.packb([seedidx,rb], use_bin_type=True))
    f.flush()
    f.truncate()
else:
  with open(nodeID + ".seed", "wb") as f:
    seedidx = 0
    rb = pysodium.randombytes(Ratchet.SECRETSIZE)
    f.write(msgpack.packb([seedidx,rb], use_bin_type=True))
if (choice == 2 or choice == 4):
  print('There will be no escrow key for initial shared secret. If you lose connectivity for an extended period of time, you may lose access to data from this producer unless you store the following value in a secure location:')
  print(nodeID + ':', hexlify(rb), " (key index", seedidx, ")")

# Second, generate identify keypair and chain, and write cryptokey config file
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
poison = msgpack.packb(poison, default=msgpack_default_pack, use_bin_type=True)
msg = [time()+_lifetime, poison, pk]
msg = prov._sk[_keys[key]].crypto_sign(msgpack.packb(msg, default=msgpack_default_pack, use_bin_type=True))
chain = msgpack.packb(msgpack.unpackb(_msgchains[key],raw=False) + [msg], default=msgpack_default_pack, use_bin_type=True)
print(nodeID, 'Public Key:', str(pk))

# Third, write config
kcs = KafkaCryptoStore(nodeID + ".config", nodeID)
kcs.store_value('maxage', _lifetime, section='crypto')
kcs.store_value('chain'+str(idx), chain, section='chains')
kcs.store_value('rot'+str(idx), _msgrot, section='allowlist')
if _msgchkrot != _msgrot:
  kcs.store_value('chainrot'+str(idx), _msgchkrot, section='allowlist')
if kcs.load_value('temporary', section='allowlist'):
  print("Found temporary ROT, removing.")
  kcs.store_value('temporary', None, section='allowlist')
# If controller, list of provisioners
if (choice == 1 and _msgchainrot != _msgrot and _msgchainrot != _msgchkrot):
  kcs.store_value('provisioners'+str(idx), _msgchainrot, section='allowlist')
if kcs.load_value('cryptokey') is None:
  kcs.store_value('cryptokey', "file#" + nodeID + ".crypto")
if kcs.load_value('ratchet') is None:
  kcs.store_value('ratchet', "file#" + nodeID + ".seed")
if ((choice == 2 or choice == 4)):
  if sole:
    kcs.store_value('mgmt_long_keyindex', False)
  else:
    kcs.store_value('mgmt_long_keyindex', True)

print('Congratulations! Provisioning is complete.')

