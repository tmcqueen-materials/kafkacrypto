from kafkacrypto.exceptions import KafkaCryptoMessageError

class KafkaCryptoMessage(object):
  """Class encapsulating crypto-handled KafkaCrypto messages. If a message is
  nominally ciphertext, some conditions mean it should be decryptable, while
  other conditions mean it will never be decryptable, so we keep track of that.

  Keyword Arguments:
                     msg (bytes): Message to turn into a KafkaCryptoMessage object
             ipt (bool,optional): Is message plaintext, or ciphertext?
                                  Default: plaintext.
            deser (obj,optional): Deserializer that can be used to attempt decryption
                                  if message is not plaintext
            topic (str,optional): Topic from which this message came
     decryptable (bool,optional): If the message is ciphertext, will it ever
                                  be decryptable (if keys become available)?
                                  Default: True.
  """
  #
  # Per instance, defined in init
  #   _msg: message bytes
  #   _ipt: plainext boolean
  # _deser: message deserializer
  # _topic: message topic
  # _decryptable: decryptability boolean
  #
  def __init__(self, msg, ipt=True, deser=None, topic=None, decryptable=True):
    if (not isinstance(msg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed message not bytes-like!")
    if (not isinstance(ipt, (bool))):
      raise KafkaCryptoMessageError("Passed plaintext flag not a boolean!")
    self._msg = msg
    self._ipt = ipt
    self._deser = deser
    self._topic = topic
    self._decryptable = decryptable
    if self._ipt:
      self._deser = None
      self._topic = None
      self._decryptable = True

  def isCleartext(self, retry=True):
    if self._deser != None and self._topic != None and self._decryptable and retry:
      # Attempt decryption
      try:
        kcm = self._deser.deserialize(self._topic, self._msg)
        if kcm._ipt:
          # success
          self._msg = kcm._msg
          self._ipt = True
          self._deser = None
          self._topic = None
          self._decryptable = True
        else:
          # failure, update decryptability status if needed
          self._decryptable = kcm._decryptable
      except:
        pass
    return self._ipt

  def isPossiblyDecryptable(self):
    return self._decryptable

  def getMessage(self, retry=True):
    if (not self.isCleartext(retry=retry)):
      raise KafkaCryptoMessageError("Message not decrypted!")
    return self._msg

  def __bytes__(self):
    return self._msg

  @staticmethod
  def fromEncryptedBytes(rawmsg,deser=None,topic=None,decryptable=True):
    if (not isinstance(rawmsg, (bytes,bytearray))):
      raise KafkaCryptoMessageError("Passed raw message not bytes-like!")
    if (len(rawmsg) == 0):
      # zero length message, never decryptable
      return KafkaCryptoMessage(b'',False,decryptable=False)
    elif not (topic is None) and not (deser is None):
      # message not yet decrypted
      return KafkaCryptoMessage(rawmsg,False,deser=deser,topic=topic,decryptable=decryptable)
    else:
      # without deser and topic, will never be decryptable
      return KafkaCryptoMessage(rawmsg,False,deser=deser,topic=topic,decryptable=False)
