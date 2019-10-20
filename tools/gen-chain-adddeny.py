#!/usr/bin/python3
import msgpack
from time import time
from getpass import getpass
from binascii import hexlify, unhexlify
from kafkacrypto.utils import PasswordProvisioner
from kafkacrypto.chain import process_chain

_lifetime = 86400
_rot = unhexlify(b'79f5303a2e1c13fb5f5c3de392004694ae1d556c09dc0003b078136f805972a1')

password = ''
while len(password) < 4:
  password = getpass('AddDeny Password (4+ chars): ')
prov = PasswordProvisioner(password, _rot)
key=prov._pk['prodcon']
poison = msgpack.packb([[b'usages',[b'key-denylist',b'key-allowlist']],[b'pathlen',1]])
tosign = msgpack.packb([time()+_lifetime,poison,key])
print('adddeny', '(', hexlify(key), '):', hexlify(tosign))
signed = unhexlify(input('Signed value (hex):'))
pk = process_chain(msgpack.packb([signed]),None,None,allowlist=[msgpack.packb([0,b'\x90',_rot])])
assert len(pk) >= 3, "Malformed Chain"

