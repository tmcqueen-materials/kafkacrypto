#!/usr/bin/python3
import pysodium
import msgpack
from time import time
from getpass import getpass
from binascii import unhexlify, hexlify
import base64
from kafkacrypto import KafkaCryptoStore
from kafkacrypto.chain import process_chain
from kafkacrypto.utils import PasswordProvisioner, str_encode

#
# Global configuration
#

_lifetime = 86400 # lifetime (1 day)
_ss0_escrow = unhexlify(b'escrow-key')
_rot = unhexlify(b'79f5303a2e1c13fb5f5c3de392004694ae1d556c09dc0003b078136f805972a1')
_msgrot = msgpack.packb([0,b'\x90',_rot])
_chainrot = _rot
_msgchainrot = _msgrot
_signedprov = { 'producer': unhexlify(b'signed-chain'),
                'consumer': unhexlify(b'signed-chain'),
                'prodcon': unhexlify(b'signed-chain'),
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

print('Beginning reprovisioning process. This should be run on the device being reprovisioned.')
nodeID = ''
while len(nodeID) < 1:
  nodeID = input('Node ID: ')

# Load existing configuration.
kcs = KafkaCryptoStore(nodeID + ".config")

try:
  pk2 = process_chain(kcs.load_value('chain',section='crypto'),None,None,allowlist=[_msgrot,_msgchainrot])
except:
  pk2 = [0,[],b'']

with open(nodeID + ".crypto", "rb") as f:
  sk = msgpack.unpackb(f.read())[0]
pk = pysodium.crypto_sign_sk_to_pk(sk)

if pk2[2] == pk:
  print('Existing Configuration:')
  print('Expiration Time:',pk2[0],'('+str((pk2[0]-time())/86400)+' days from now)')
  print('Poison Array:',msgpack.unpackb(pk2[1]))
  print('Public Key:',pk2[2].hex()) 
else:
  print('No valid chain. Public key:',pk.hex())

correct = ''
while len(correct)<1:
  correct = input('Is this correct (y/N)? ')
if correct[0].lower() == 'y':
  correct = True
else:
  correct = False

assert correct, 'Wrong file according to the user.'

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
elif (choice == 3 and not limited):
  key = 'consumer'
elif (choice == 4 and limited):
  key = 'prodcon-limited'
elif (choice == 4 and not limited):
  key = 'prodcon'
else:
  assert False,'Invalid combination of choices!'

password = ''
while len(password) < 12:
  password = getpass('Provisioning Password (12+ chars): ')
prov = PasswordProvisioner(password, _rot)

# Check we have appropriate chains
assert (len(_msgchains[key]) > 0), 'A trusted chain for ' + key + ' is missing. Use generate-chains.py (and possibly sign with another key), and add to resign-node.py.'
checkchain = process_chain(_msgchains[key],None,None,allowlist=[_msgrot,_msgchainrot])
assert (len(checkchain) >= 3 and checkchain[2] == prov._pk[_keys[key]]), 'Malformed chain for ' + key + '. Did you enter your password correctly and have msgchain rot set appropriately?'

topics = None
while topics is None:
  topic = input('Enter a space separated list of topics this ' + key + ' will use: ')
  topics = list(set(map(lambda i: i.split('.',1)[0].encode('utf-8'), topic.split())))
  if (len(topics) < 1):
    ans = input('Are you sure you want to allow all topics (y/N)?')
    if (len(ans) == 0 or ans[0].lower() != 'y'):
      topics = None
    else:
      topics = [b'^.*$']

pathlen = ''
pathlen = input('Enter a maximum pathlength (-1 for no limit; default 1):')
if len(pathlen)<1:
  pathlen=1
else:
  pathlen=int(pathlen)

print('Root topics will be:',topics)
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

# Load secret key
with open(nodeID + ".crypto", "rb") as f:
  sk = msgpack.unpackb(f.read())[0]
assert (pysodium.crypto_sign_sk_to_pk(sk) == pk), 'Crypto file does not contain expected secret key.'
pk = pysodium.crypto_sign_sk_to_pk(sk)

poison = [[b'usages',_usages[key]]]
if len(topics) > 0:
  poison.append([b'topics',topics])
if pathlen != -1:
  poison.append([b'pathlen',pathlen])
poison = msgpack.packb(poison)
msg = [time()+_lifetime, poison, pk]
print('Unsigned leaf:',base64.b64encode(msgpack.packb(msg)))
msg = pysodium.crypto_sign(msgpack.packb(msg), prov._sk[_keys[key]])
chain = msgpack.packb(msgpack.unpackb(_msgchains[key]) + [msg])
print(nodeID, 'public key:', hexlify(pysodium.crypto_sign_sk_to_pk(sk)))

# Update chain
kcs.store_value('chain',chain,section='crypto')
