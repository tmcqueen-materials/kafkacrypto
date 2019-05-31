from time import time
import traceback
import pysodium
import msgpack
from kafkacrypto.chain import process_chain

class Provisioners(object):
  """Class utilizing file-backed storage to validate key requests

  Keyword Arguments:
          file (str,file): Filename or File IO object for storing provisioners.
                           Must be seekable, with read/write permission, and
                           honor sync requests.
  """
  #
  # Per instance, defined in init
  #      __file: File object
  #      __spks: list of allowed provisioner public keys
  #
  def __init__(self, file):
    if (isinstance(file, (str))):
      file = open(file, 'rb', 0)
    self.__file = file
    self.__file.seek(0,0)
    contents = msgpack.unpackb(self.__file.read())
    self.__spks = contents
    self.__file.close()

  def reencrypt_request(self, topic, cryptokey, msgkey=None, msgval=None):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    #
    # msgval should be a msgpacked chain chaining to a provisioner.
    # The last item in the array is the encrypted public key to retransmit.
    #
    try:
      pk = None
      for prov in self.__spks:
        try:
          pk = process_chain(topic,prov,msgval,b'key-encrypt-subscribe')
        except:
          pass
      if (prov is None):
        raise ValueError("Chain not signed by authorized provisioner.")
      tmp, msg = cryptokey.signed_epk(topic, epk=pk[2])
    except Exception as e:
      print("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return (None, None)
    return (msgkey, msg)
