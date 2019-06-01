#!/usr/bin/python3
import msgpack
from getpass import getpass
from binascii import hexlify, unhexlify
from kafkacrypto.utils import PasswordProvisioner

_rot = unhexlify(b'79f5303a2e1c13fb5f5c3de392004694ae1d556c09dc0003b078136f805972a1')
_usages = {  'producer': [b'key-encrypt'],
             'consumer': [b'key-encrypt-request',b'key-encrypt-subscribe'],
             'prodcon': [b'key-encrypt',b'key-encrypt-request',b'key-encrypt-subscribe'],
             }

password = ''
while len(password) < 12:
  password = getpass('Provisioning Password (12+ chars): ')
prov = PasswordProvisioner(password, _rot)
for kn in _usages.keys():
  key=prov._pk[kn]
  poison = msgpack.packb([[b'usages',_usages[kn]]])
  tosign = msgpack.packb([0,poison,key])
  print(kn, '(', hexlify(key), '):', hexlify(tosign))
