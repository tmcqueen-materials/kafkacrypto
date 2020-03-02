from time import time
import traceback
import pysodium
import msgpack
import logging
from kafkacrypto.chain import process_chain

class Provisioners(object):
  """Class validating key requests

  Keyword Arguments:
         allowlist (array): List of allowlisted public keys (provisioners)
          denylist (array): Optional list of denylisted public keys
  """
  def __init__(self, allowlist=None, denylist=None):
    self._logger = logging.getLogger(__name__)
    self.__allowlist = allowlist
    self.__denylist = denylist

  def reencrypt_request(self, topic, cryptoexchange, msgkey=None, msgval=None):
    if (isinstance(topic,(bytes,bytearray))):
      self._logger.debug("topic provided as bytes (should be string)")
      topic = topic.decode('utf-8')
    #
    # msgval should be a msgpacked chain chaining to a provisioner.
    # The last item in the array is the encrypted public key to retransmit.
    #
    try:
      pk = None
      try:
        pk = process_chain(msgval,topic,'key-encrypt-subscribe',allowlist=self.__allowlist,denylist=self.__denylist)
      except:
        pass
      if (pk is None):
        raise ValueError("Request did not validate.")
      msg = cryptoexchange.signed_epk(topic, epk=pk[2])
    except Exception as e:
      self._logger.warning("".join(traceback.format_exception(etype=type(e), value=e, tb=e.__traceback__)))
      return (None, None)
    return (msgkey, msg)
