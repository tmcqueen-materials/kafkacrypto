from time import time
import traceback
import pysodium
import msgpack
from kafkacrypto.chain import process_chain

class Provisioners(object):
  """Class validating key requests

  Keyword Arguments:
      provisioners (array): List of public keys of allowed provisioners
          denylist (array): Optional list of denylisted public keys
  """
  #
  # Per instance, defined in init
  #      __spks: list of allowed provisioner public keys
  #
  def __init__(self, provisioners=[], denylist=None):
    self.__spks = provisioners
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
      for prov in self.__spks:
        try:
          pk = process_chain(topic,prov,msgval,b'key-encrypt-subscribe',denylist=self.__denylist)
        except:
          pass
      if (prov is None):
        raise ValueError("Chain not signed by authorized provisioner.")
      tmp, msg = cryptoexchange.signed_epk(topic, epk=pk[2])
    except Exception as e:
      print("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return (None, None)
    return (msgkey, msg)
