from kafkacrypto.exceptions import KafkaCryptoMessageError

class KafkaCryptoMessage(object):
  """Class encapsulating crypto-handled KafkaCrypto messages. 

  Keyword Arguments:
              msg (bytes): Message to turn into a KafkaCryptoMessage object
      ipt (bool,optional): Is message plaintext, or ciphertext? 
                           Default: plaintext.
  """
  #
  # Per instance, defined in init
  # _msg: message bytes
  # _ipt: plainext boolean
  #
  def __init__(self, msg, ipt=True):
    if (not isinstance(msg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed message not bytes-like!")
    if (not isinstance(ipt, (bool))):
      raise KafkaCryptoMessageError("Passed plaintext flag not a boolean!")
    self._msg = msg
    self._ipt = ipt

  def isCleartext(self):
    return self._ipt

  def getMessage(self):
    if (not self.isCleartext()):
      raise KafkaCryptoMessageError("Message not decrypted!")
    return self._msg

  def __bytes__(self):
    return self._msg

  @staticmethod
  def fromBytes(rawmsg):
    if (not isinstance(rawmsg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed raw message not bytes-like!")
    if (rawmsg[0] == 0):
      return KafkaCryptoMessage(rawmsg[1:],True)
    else:
      return KafkaCryptoMessage(rawmsg,False)
