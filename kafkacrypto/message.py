from kafkacrypto.exceptions import KafkaCryptoMessageError

class KafkaCryptoMessage(object):
  """Class encapsulating crypto-handled KafkaCrypto messages. 

  Keyword Arguments:
              msg (bytes): Message to turn into a KafkaCryptoMessage object
      ipt (bool,optional): Is message plaintext, or ciphertext? 
                           Default: plaintext.
     deser (obj,optional): Deserializer that can be used to attempt decryption
                           if message is not plaintext
     topic (str,optional): Topic from which this message came
  """
  #
  # Per instance, defined in init
  #   _msg: message bytes
  #   _ipt: plainext boolean
  # _deser: message deserializer
  # _topic: message topic
  #
  def __init__(self, msg, ipt=True, deser=None, topic=None):
    if (not isinstance(msg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed message not bytes-like!")
    if (not isinstance(ipt, (bool))):
      raise KafkaCryptoMessageError("Passed plaintext flag not a boolean!")
    self._msg = msg
    self._ipt = ipt
    self._deser = deser
    self._topic = topic
    if self._ipt:
      self._deser = None
      self._topic = None

  def isCleartext(self, retry=True):
    if self._deser != None and self._topic != None and retry:
      # Attempt decryption
      try:
        kcm = self._deser.deserialize(self._topic, self._msg)
        if kcm._ipt:
          # success
          self._msg = kcm._msg
          self._ipt = True
          self._deser = None
          self._topic = None
      except:
        pass
    return self._ipt

  def getMessage(self, retry=True):
    if (not self.isCleartext(retry=retry)):
      raise KafkaCryptoMessageError("Message not decrypted!")
    return self._msg

  def __bytes__(self):
    return self._msg

  @staticmethod
  def fromBytes(rawmsg,deser=None,topic=None):
    if (not isinstance(rawmsg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed raw message not bytes-like!")
    if (len(rawmsg) == 0):
      return KafkaCryptoMessage(b'',False)
    elif (rawmsg[0] == 0):
      return KafkaCryptoMessage(rawmsg[1:],True)
    else:
      return KafkaCryptoMessage(rawmsg,False,deser=deser,topic=topic)
