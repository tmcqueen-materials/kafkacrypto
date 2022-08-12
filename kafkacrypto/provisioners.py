from time import time
from kafkacrypto.utils import format_exception_shim
import pysodium
import msgpack
import logging
from kafkacrypto.chain import process_chain, ProcessChainError

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
    # The third item in the array is the public key to retransmit. The fourth item is
    # random0.
    #
    try:
      pk = None
      try:
        pk,pkprint = process_chain(msgval,topic,'key-encrypt-subscribe',allowlist=self.__allowlist,denylist=self.__denylist)
      except ProcessChainError as pce:
        raise pce
      except:
        pass
      if (pk is None):
        if not (pkprint is None):
          raise ProcessChainError("Request did not validate: ", pkprint)
        else:
          raise ValueError("Request did not validate!")
      # TODO: can add sanity checking of random0 and the public key if desired.
      msg = cryptoexchange.signed_epks(topic, epks=[pk[2]], random0=pk[3])[0]
    except Exception as e:
      self._logger.warning("".join(format_exception_shim(e)))
      return (None, None)
    return (msgkey, msg)
