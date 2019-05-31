from kafkacrypto.keygenerator import KeyGenerator
from kafkacrypto.exceptions import KafkaCryptoRatchetError
import pysodium
import msgpack

class Ratchet(KeyGenerator):
  """Class utilizing file-backed storage to provide a ratcheting key generator.

  Keyword Arguments:
          file (str,file): Filename or File IO object for storing ratchet info.
                           Must be seekable, with read/write permission, and
                           honor sync requests.
  """
  #
  # Ratchet global configuration. These define the parameters
  # to generate the *next* secret key based on the current one.
  #
  __ctx = b'ratchet' + (b'\x00' * 9)

  #
  # Per instance, defined in init
  # __file: File object
  # __keyidx: unsigned integer index of current key index/ID
  #
  def __init__(self, file):
    super().__init__()
    if (isinstance(file, (str))):
      file = open(file, 'rb+', 0)
    self.__file = file
    self.increment()

  def increment(self):
    self.__file.seek(0,0)
    contents = msgpack.unpackb(self.__file.read())
    self.__keyidx = contents[0]
    self.rekey(contents[1])
    self.__file.seek(0,0)
    newkey,nonce = self.generate(ctx=self.__ctx,keysize=self.SECRETSIZE,noncesize=0)
    self.__file.write(msgpack.packb([self.__keyidx+1,newkey]))
    self.__file.flush()
    self.__file.seek(0,0)

  def keyidx(self):
    return self.__keyidx

  def get_key_value_generators(self, topic):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    # pysodium silently computes the hash of an empty string if input is not bytes, so check for
    # and catch that.
    if (not isinstance(topic, (bytes,bytearray))):
      raise KafkaCryptoRatchetError("Topic is not bytes!")
    hash = pysodium.crypto_hash_sha256(topic)
    key,nonce = self.generate(salt=hash[0:self.SALTSIZE],ctx=hash[self.SALTSIZE:],keysize=self.SECRETSIZE,noncesize=0)
    return (self.keyidx(), KeyGenerator.key_generator(key), KeyGenerator.value_generator(key))

