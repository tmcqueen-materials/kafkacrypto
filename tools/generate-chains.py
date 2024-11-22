#!/usr/bin/python3
import msgpack
from getpass import getpass
from binascii import hexlify, unhexlify
from kafkacrypto.provisioners import PasswordProvisioner
from kafkacrypto.utils import msgpack_default_pack
#
# Need to ask for keytype to load appropriate global configuration
#
keytype = 0
while not (keytype in [1,4]):
  try:
    keytype = int(input('Key type (1 = Ed25519 (default), 4 = Ed25519+SLH-DSA-SHAKE-128f)? '))
  except ValueError:
    keytype = 1

if keytype == 1:
  # Ed25519
  _rot = unhexlify(b'rot-key-here')
elif keytype == 4:
  # Ed25519+SLH-DSA-SHAKE-128f
  _rot = unhexlify(b'rot-key-here')

# Common configs
_usages = {  'producer': ['key-encrypt'],
             'consumer': ['key-encrypt-request','key-encrypt-subscribe'],
             'prodcon': ['key-encrypt','key-encrypt-request','key-encrypt-subscribe'],
             }

password = ''
while len(password) < 12:
  password = getpass('Provisioning Password (12+ chars): ')
prov = PasswordProvisioner(password, _rot, keytype=keytype)
for kn in _usages.keys():
  key=prov._pk[kn]
  skey=prov._sk[kn]
  poison = msgpack.packb([['usages',_usages[kn]],['topics',['^.*$']],['pathlen', 2]], default=msgpack_default_pack, use_bin_type=True)
  tosign = msgpack.packb([0,poison,key], default=msgpack_default_pack, use_bin_type=True)
  poison = msgpack.packb([['usages',['key-denylist']],['pathlen',0]], default=msgpack_default_pack, use_bin_type=True)
  revoke_core = skey.crypto_sign(msgpack.packb([0,poison,key], default=msgpack_default_pack, use_bin_type=True))
  poison = msgpack.packb([['usages',['key-denylist']],['pathlen',1]],default=msgpack_default_pack,  use_bin_type=True)
  revoke = msgpack.packb([msgpack.packb([0,poison,key], default=msgpack_default_pack, use_bin_type=True),revoke_core], default=msgpack_default_pack, use_bin_type=True)
  print(kn, '(', hexlify(bytes(key)), '):', hexlify(tosign), '(sk:', hexlify(bytes(skey)),')')
  print('                Self-Signed Revocation:', hexlify(revoke))
  
print('Once signed, you produce msgpacked chains by doing msgpack.packb([b"signed"], default=msgpack_default_pack, use_bin_type=True)')

