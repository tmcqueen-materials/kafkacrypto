#!/usr/bin/python3
import pysodium
import msgpack
from time import time
from getpass import getpass
from binascii import unhexlify, hexlify
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.chain import process_chain
from kafkacrypto.utils import PasswordProvisioner

#
# Global configuration
#

_lifetime = 31622400 # lifetime (1 year)
_ss0_escrow = unhexlify(b'7e301be3922d8166e30be93c9ecc2e18f71400fe9e6407fd744f4a542bcab934')
_rot = unhexlify(b'79f5303a2e1c13fb5f5c3de392004694ae1d556c09dc0003b078136f805972a1')
_msgrot = msgpack.packb([0,b'\x90',_rot])
_chainrot = _rot
_msgchainrot = _msgrot
_signedprov = { 'producer': unhexlify(b'signed key here'),
                'consumer': unhexlify(b'signed key here'),
                'prodcon': unhexlify(b'signed key here'),
                }
_keys =     {    'producer': 'producer',
                 'consumer': 'consumer',
                 'prodcon': 'prodcon',
                 'prodcon-limited': 'prodcon',
                 'consumer-limited': 'consumer',
                 'controller': 'consumer',
                 }
_msgchains = { 'producer': msgpack.packb([_signedprov[_keys['producer']]]),
               'consumer': msgpack.packb([_signedprov[_keys['consumer']]]),
               'prodcon': msgpack.packb([_signedprov[_keys['prodcon']]]),
               'prodcon-limited': msgpack.packb([_signedprov[_keys['prodcon-limited']]]),
               'consumer-limited': msgpack.packb([_signedprov[_keys['consumer-limited']]]),
               'controller': msgpack.packb([_signedprov[_keys['controller']]]),
             }
_usages = {      'producer': [b'key-encrypt'],
                 'consumer': [b'key-encrypt-request',b'key-encrypt-subscribe'],
                 'prodcon': [b'key-encrypt',b'key-encrypt-request',b'key-encrypt-subscribe'],
                 'prodcon-limited': [b'key-encrypt',b'key-encrypt-subscribe'],
                 'consumer-limited': [b'key-encrypt-subscribe'],
                 'controller': [b'key-encrypt-request'],
                 }

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

if (choice == 2 or choice == 4):
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
    limited = input('Limit the consumer to only functioning with controllers (Y/n)? ')
  if limited[0].lower() == 'n':
    limited = False
  else:
    limited = True

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

password = ''
while len(password) < 12:
  password = getpass('Provisioning Password (12+ chars): ')
prov = PasswordProvisioner(password, _rot)

# Check we have appropriate chains
if (choice == 1):
  # Controllers must be signed by ROT
  _msgchkrot = _msgrot
else:
  # Everyone else by the Chain ROT (may = ROT)
  _msgchkrot = _msgchainrot
assert (len(_msgchains[key]) > 0), 'A trusted chain for ' + key + ' is missing. Use generate-chains.py (and possibly sign with another key), and add to provision.py.'
pk = process_chain(b'',_msgchkrot,_msgchains[key],b'')
assert (len(pk) >= 3 and pk[2] == prov._pk[_keys[key]]), 'Malformed chain for ' + key + '. Did you enter your password correctly and have msgchain rot set appropriately?'

topics = None
while topics is None:
  topic = input('Enter a space separated list of topics this ' + key + ' will use: ')
  topics = list(set(map(lambda i: i.split('.',1)[0].encode('utf-8'), topic.split())))
  if (len(topics) < 1):
    ans = input('Are you sure you want to allow all topics (y/N)?')
    if (len(ans) == 0 or ans[0].lower() != 'y'):
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
if len(_ss0_escrow) > 0:
  print('Escrow key used for initial shared secret. If you lose connectivity for an extended period of time, you will need the following (and the private key for the escrow public key) to access data')
  print('Escrow public key:', hexlify(_ss0_escrow))
  print(nodeID + ' escrow value: ', hexlify(pysodium.crypto_box_seal(rb, _ss0_escrow)))
else:
  print('No escrow key for initial shared secret. If you lose connectivity for an extended period of time, you may lose access to data unless you store the following value in a secure location:')
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
  f.write(msgpack.packb([_lifetime,_msgrot,_msgchkrot,sk,chain]))
  print(nodeID, 'public key:', hexlify(pysodium.crypto_sign_sk_to_pk(sk)))

# Third, write config defaults
DEFAULTS = { 'TOPIC_SEPARATOR': b'.',   # separator of topic name components, used to find root name and subs/keys
               'TOPIC_SUFFIX_REQS': b'.reqs', # suffixes should begin with separator or things will not work!
               'TOPIC_SUFFIX_KEYS': b'.keys',
               'TOPIC_SUFFIX_SUBS': b'.subs', # change to be same as REQS if this is a controller-less setup
               'CRYPTO_MAX_PGEN_AGE': 604800,  # in s
               'CRYPTO_SUB_INTERVAL': 60,      # in s
               'CRYPTO_RATCHET_INTERVAL': 86400,  # in s
               'MGMT_POLL_INTERVAL': 500, # in ms
               'MGMT_POLL_RECORDS': 8,    # poll fetches by topic-partition. So limit number per call to sample all tps
               'MGMT_SUBSCRIBE_INTERVAL': 300, # in sec
               'MGMT_LONG_KEYINDEX': True,
             }
if ((choice == 2 or choice == 4) and sole == True):
  DEFAULTS['MGMT_LONG_KEYINDEX'] = False

with open(nodeID + ".config", "wb") as f:
  f.write(msgpack.packb(DEFAULTS))
