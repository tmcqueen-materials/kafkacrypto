#!/usr/bin/python3
import pysodium
import msgpack
from time import time
from getpass import getpass
from binascii import unhexlify, hexlify
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.chain import process_chain
from kafkacrypto.utils import PasswordProvisioner, PasswordROT

#
# Global configuration
#

_lifetime = 31622400 # lifetime (1 year)
_usages = {  'producer': [b'key-encrypt'],
             'consumer': [b'key-encrypt-request',b'key-encrypt-subscribe'],
             'prodcon': [b'key-encrypt',b'key-encrypt-request',b'key-encrypt-subscribe'],
             'prodcon-limited': [b'key-encrypt',b'key-encrypt-subscribe'],
             'consumer-limited': [b'key-encrypt-subscribe'],
             'controller': [b'key-encrypt-request'],
             }
_keys = {    'producer': 'producer',
             'consumer': 'consumer',
             'prodcon': 'prodcon',
             'prodcon-limited': 'prodcon',
             'consumer-limited': 'consumer',
             'controller': 'consumer',
             }


# Get ROT first
password = ''
while len(password) < 12:
  password = getpass('ROT Password (12+ chars): ')
rot = PasswordROT(password)

_rot = rot._pk
_msgrot = msgpack.packb([0,b'\x90',_rot])
_chainrot = _rot
_msgchainrot = _msgrot

# Get Provisioning keys second
password = ''
while len(password) < 6:
  password = getpass('Provisioning Password (6+ chars): ')
prov = PasswordProvisioner(password, _rot)

# Generate signed chains
_signedprov = { 'producer': None,
            'consumer': None,
            'prodcon': None,
          }
for kn in _signedprov.keys():
  key=prov._pk[kn]
  poison = msgpack.packb([[b'usages',_usages[kn]]])
  tosign = msgpack.packb([0,poison,key])
  _signedprov[kn] = pysodium.crypto_sign(tosign, rot._sk)

_msgchains = { 'producer': msgpack.packb([_signedprov[_keys['producer']]]),
               'consumer': msgpack.packb([_signedprov[_keys['consumer']]]),
               'prodcon': msgpack.packb([_signedprov[_keys['prodcon']]]),
               'prodcon-limited': msgpack.packb([_signedprov[_keys['prodcon-limited']]]),
               'consumer-limited': msgpack.packb([_signedprov[_keys['consumer-limited']]]),
               'controller': msgpack.packb([_signedprov[_keys['controller']]]),
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

if (choice == 2	or choice == 4):
  sole = ''
  while len(sole)<1:
    sole = input('Will the producer be the only producer of the topics it produces on (y/N)? ')
  if sole[0].lower() == 'y':
    sole = True
  else:
    sole = False

if (choice == 3 or choice == 4):
  limited = ''
  while len(limited)<1:
    limited = input('Limit the consumer to only functioning with controllers (y/N)? ')
  if limited[0].lower() == 'y':
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
  _chainrot = _rot
  _msgchainrot = _msgrot
assert (len(_msgchains[key]) > 0), 'A trusted chain for ' + key + ' is missing. This should not happen with simple-provision, please report as a bug.'
pk = process_chain(b'',_msgchainrot,_msgchains[key],b'')
assert (len(pk) >= 3 and pk[2] == prov._pk[_keys[key]]), 'Malformed chain for ' + key + '. Did you enter your passwords correctly?'

topics = None
while topics is None:
  topic = input('Enter a space separated list of topics this ' + key + ' will use: ')
  topics = list(set(map(lambda i: i.split('.',1)[0].encode('utf-8'), topic.split())))
  if (len(topics) < 1):
    ans = input('Are you sure you want to allow all topics (Y/n)?')
    if (ans[0].lower() == 'n'):
      topics = None

print('Root topics will be:')
print(topics)
print('Lifetime of initial crypto configuration will be', _lifetime/86400, 'days.')
print('')

ans = ''
while len(ans) < 1 or (ans[0].lower() != 'n' and ans[0].lower() != 'y'):
  ans = input('Are you sure all the information above is correct (yes/no)? ')

assert (ans[0].lower() == 'y'), 'Aborting per user request.'

# If controller, list of provisioners
if (choice == 1):
  with open(nodeID + ".provisioners", "wb") as f:
    f.write(msgpack.packb([_msgchainrot]))

# Generate KDF seed first
with open(nodeID + ".seed", "wb") as f:
  rb = pysodium.randombytes(Ratchet.SECRETSIZE)
  f.write(msgpack.packb([0,rb]))
if (choice == 2 or choice == 4):
  print('There will be no escrow key for initial shared secret. If you lose connectivity for an extended period of time, you may lose access to data from this producer unless you store the following value in a secure location:')
  print(nodeID + ':', hexlify(rb))

# Second, write cryptokey config file
with open(nodeID + ".crypto", "wb") as f:
  pk,sk = pysodium.crypto_sign_keypair()
  if len(topics) > 0:
    poison = msgpack.packb([[b'topics',topics],[b'usages',_usages[key]]])
  else:
    poison = msgpack.packb([[b'usages',_usages[key]]])
  msg = [time()+_lifetime, poison, pk]
  msg = pysodium.crypto_sign(msgpack.packb(msg), prov._sk[_keys[key]])
  chain = msgpack.packb(msgpack.unpackb(_msgchains[key]) + [msg])
  f.write(msgpack.packb([_lifetime,_msgrot,_msgchainrot,sk,chain]))
  print(nodeID, 'public key:', hexlify(pysodium.crypto_sign_sk_to_pk(sk)))

# Third, write config defaults
DEFAULTS = { 'TOPIC_SEPARATOR': b'.',   # separator of topic name components, used to find root name and subs/keys
               'TOPIC_SUFFIX_REQS': b'.reqs', # suffixes should begin with separator or things will not work!
               'TOPIC_SUFFIX_KEYS': b'.keys',
               'TOPIC_SUFFIX_SUBS': b'.reqs', # change to be .subs for a controller-based setup
               'MGMT_POLL_INTERVAL': 500, # in ms
               'MGMT_POLL_RECORDS': 8,    # poll fetches by topic-partition. So limit number per call to sample all tps
               'MGMT_SUBSCRIBE_INTERVAL': 300, # in sec
               'MGMT_LONG_KEYINDEX': True,
             }
if (sole == True):
  DEFAULTS['MGMT_LONG_KEYINDEX'] = False

with open(nodeID + ".config", "wb") as f:
  f.write(msgpack.packb(DEFAULTS))
