from time import time
import traceback
import pysodium
import msgpack
from kafkacrypto.chain import process_chain

class Provisioners(object):
  """Class validating key requests

  Keyword Arguments:
         allowlist (array): List of allowlisted public keys (provisioners)
          denylist (array): Optional list of denylisted public keys
  """
  def __init__(self, allowlist=None, denylist=None):
    self.__allowlist = allowlist
    self.__denylist = denylist

  def reencrypt_request(self, topic, cryptoexchange, msgkey=None, msgval=None):
    if (isinstance(topic,(str))):
      topic = bytes(topic, 'utf-8')
    #
    # msgval should be a msgpacked chain chaining to a provisioner.
    # The last item in the array is the encrypted public key to retransmit.
    #
    try:
      pk = None
      try:
        pk = process_chain(msgval,topic,b'key-encrypt-subscribe',allowlist=self.__allowlist,denylist=self.__denylist)
      except:
        pass
      if (pk is None):
        raise ValueError("Chain not signed by authorized provisioner.")
      tmp, msg = cryptoexchange.signed_epk(topic, epk=pk[2])
    except Exception as e:
      print("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return (None, None)
    return (msgkey, msg)
