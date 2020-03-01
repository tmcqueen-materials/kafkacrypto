#!/usr/bin/python3
import pysodium
import msgpack
from configparser import ConfigParser
from time import time
from getpass import getpass
from os import path
from binascii import unhexlify, hexlify
from kafkacrypto.ratchet import Ratchet
from kafkacrypto.chain import process_chain
from kafkacrypto.utils import PasswordProvisioner
from kafkacrypto import KafkaCryptoStore

#
# Global configuration
#

_lifetime = 6048000 # lifetime (1 week)
_lifetime_controller = 31622400 # controller lifetime (1 year)
_ss0_escrow = unhexlify(b'escrow-key-here')
_rot = unhexlify(b'79f5303a2e1c13fb5f5c3de392004694ae1d556c09dc0003b078136f805972a1')
_msgrot = msgpack.packb([0,b'\x90',_rot], use_bin_type=True)
_chainrot = _rot
_msgchainrot = _msgrot
_signedprov = {  'producer' : unhexlify(b'chain-here'),
                 'consumer' : unhexlify(b'chain-here'),
                  'prodcon' : unhexlify(b'chain-here'),
              }
_keys =     {    'producer': 'producer',
                 'consumer': 'consumer',
                 'prodcon': 'prodcon',
                 'prodcon-limited': 'prodcon',
                 'consumer-limited': 'consumer',
                 'controller': 'consumer',
                 }
_msgchains = { 'producer': msgpack.packb([_signedprov[_keys['producer']]], use_bin_type=True),
               'consumer': msgpack.packb([_signedprov[_keys['consumer']]], use_bin_type=True),
               'prodcon': msgpack.packb([_signedprov[_keys['prodcon']]], use_bin_type=True),
               'prodcon-limited': msgpack.packb([_signedprov[_keys['prodcon-limited']]], use_bin_type=True),
               'consumer-limited': msgpack.packb([_signedprov[_keys['consumer-limited']]], use_bin_type=True),
               'controller': msgpack.packb([_signedprov[_keys['controller']]]),
             }
_usages = {      'producer': [b'key-encrypt'],
                 'consumer': [b'key-encrypt-request',b'key-encrypt-subscribe'],
                 'prodcon': [b'key-encrypt',b'key-encrypt-request',b'key-encrypt-subscribe'],
                 'prodcon-limited': [b'key-encrypt',b'key-encrypt-subscribe'],
                 'consumer-limited': [b'key-encrypt-subscribe'],
                 'controller': [b'key-encrypt-request'],
                 'chain-server': [b'key-encrypt',b'key-encrypt-subscribe'],
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
print('5. Chain Server')
choice = 0
while choice<1 or choice>5:
  try:
    choice = int(input('? '))
  except ValueError:
    pass

sole = False

if (choice == 3 or choice == 4):
  limited = ''
  limited = input('Limit the consumer to only functioning with controllers (Y/n)? ')
  if len(limited) > 0 and limited[0].lower() == 'n':
    limited = False
  else:
    limited = True

if (choice == 1):
  _lifetime = _lifetime_controller
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
elif (choice == 5):
  _lifetime = _lifetime_controller
  key = 'chain-server'
else:
  assert False,'Invalid combination of choices!'

if choice<5:
  # use an existing provisioner
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
  pk = process_chain(_msgchains[key],None,None,allowlist=[_msgchkrot])
  assert (len(pk) >= 3 and pk[2] == prov._pk[_keys[key]]), 'Malformed chain for ' + key + '. Did you enter your password correctly and have msgchain rot set appropriately?'

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

if choice<5:
  pathlen=1
else:
  pathlen=2
pathlen = input('Enter a maximum pathlength (-1 for no limit; default ' + str(pathlen) + '):')
if len(pathlen)<1:
  if choice<5:
    pathlen=1
  else:
    pathlen=2
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

# Generate KDF seed first
if choice<5:
# Generate KDF seed first, if needed
  if path.exists(nodeID + ".seed"):
    with open(nodeID + ".seed", "rb") as f:
      idx,rb = msgpack.unpackb(f.read(),raw=True)
  else:
    with open(nodeID + ".seed", "wb") as f:
      idx = 0
      rb = pysodium.randombytes(Ratchet.SECRETSIZE)
      f.write(msgpack.packb([idx,rb], use_bin_type=True))
  if len(_ss0_escrow) > 0:
    print('Escrow key used for initial shared secret. If you lose connectivity for an extended period of time, you will need the following (and the private key for the escrow public key) to access data')
    print('Escrow public key:', hexlify(_ss0_escrow))
    print(nodeID + ' escrow value: ', hexlify(pysodium.crypto_box_seal(rb, _ss0_escrow)), " (key index", idx, ")")
  else:
    print('No escrow key for initial shared secret. If you lose connectivity for an extended period of time, you may lose access to data unless you store the following value in a secure location:')
    print(nodeID + ':', hexlify(rb), " (key index", idx, ")")

# Second, generate identify keypair and chain, and write cryptokey config file
if path.exists(nodeID + ".crypto"):
  with open(nodeID + ".crypto", "rb") as f:
    sk,_ = msgpack.unpackb(f.read(),raw=True)
    pk = pysodium.crypto_sign_sk_to_pk(sk)
else:
  pk,sk = pysodium.crypto_sign_keypair()
  with open(nodeID + ".crypto", "wb") as f:
    f.write(msgpack.packb([sk,pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)], use_bin_type=True))

poison = [[b'usages',_usages[key]]]
if len(topics) > 0:
  poison.append([b'topics',topics])
if pathlen != -1:
  poison.append([b'pathlen',pathlen])
poison = msgpack.packb(poison, use_bin_type=True)
msg = [time()+_lifetime, poison, pk]
if choice<5:
  msg = pysodium.crypto_sign(msgpack.packb(msg, use_bin_type=True), prov._sk[_keys[key]])
  chain = msgpack.packb(msgpack.unpackb(_msgchains[key],raw=True) + [msg], use_bin_type=True)
else:
  print('New Chain Server', '(', hexlify(pk), '):', hexlify(msgpack.packb(msg, use_bin_type=True)))
  msg = unhexlify(input('ROT Signed Value (hex):'))
  chain = msgpack.packb([msg], use_bin_type=True)
  pk2 = process_chain(chain,None,None,allowlist=[_msgrot])
  assert len(pk2) >= 3, "Malformed ROT Signed Value"
print(nodeID, 'public key:', hexlify(pk))

# Third, write config
kcs = KafkaCryptoStore(nodeID + ".config", nodeID)
kcs.store_value('chain', chain, section='crypto')
if kcs.load_value('cryptokey') is None:
  kcs.store_value('cryptokey', "file#" + nodeID + ".crypto")
kcs.store_value('rot', _msgrot, section='allowlist')
if kcs.load_value('temporary', section='allowlist'):
  print("Found temporary ROT, removing.")
  kcs.store_value('temporary', None, section='allowlist')
if choice<5:
  kcs.store_value('maxage', _lifetime, section='crypto')
  if _msgchkrot != _msgrot:
    kcs.store_value('chainrot', _msgchkrot, section='allowlist')
  # If controller, list of provisioners
  if (choice == 1 and _msgchainrot != _msgrot and _msgchainrot != _msgchkrot):
    kcs.store_value('provisioners0', _msgchainrot, section='allowlist')
  if kcs.load_value('ratchet') is None:
    kcs.store_value('ratchet', "file#" + nodeID + ".seed")
  if ((choice == 2 or choice == 4)):
    if sole:
      kcs.store_value('mgmt_long_keyindex', False)
    else:
      kcs.store_value('mgmt_long_keyindex', True)
elif choice == 5:
  kcs.store_value("test", "test", section="chainkeys")
  kcs.store_value("test", None, section="chainkeys")

print('Congratulations! Provisioning is complete.')
