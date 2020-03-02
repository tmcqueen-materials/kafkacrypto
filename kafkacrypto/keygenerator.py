from kafkacrypto.exceptions import KafkaCryptoGeneratorError
import pysodium
import logging

class KeyGenerator(object):
  """Class implementing a blake2b-based key/nonce generator

  Keyword Arguments:
          secret (bytes, optional): 32-byte Secret used to generate keys
             ctx (bytes, optional): 16-byte context used to generate keys
  """
  #
  # Generator global configuration.
  #
  SECRETSIZE = 32
  KEYSIZE = 32
  NONCESIZE = 24
  SALTSIZE = 16
  MSG = b''

  #
  # Per instance, defined in init
  # __secret: Secret used to generate keys
  #    __ctx: Default context used to generate keys
  #   __salt: Default salt, incremented after each invocation
  #
  def __init__(self, secret=b'\x00'*SECRETSIZE, ctx=b'generator'+(b'\x00'*7)):
    self._logger = logging.getLogger(__name__)
    if (not isinstance(ctx, (bytes,bytearray))):
      raise KafkaCryptoGeneratorError("Context is not bytes!")
    self.__secret = None
    self.__ctx = ctx
    self.rekey(secret)

  def rekey(self, secret):
    if (not isinstance(secret, (bytes,bytearray)) or len(secret) != self.SECRETSIZE or (not (self.__secret is None) and secret == self.__secret)):
      raise KafkaCryptoGeneratorError("Secret is malformed!")
    self.__secret = secret
    self.__salt = b'\x00' * self.SALTSIZE

  def generate(self,msg=MSG,ctx=None,salt=None,keysize=KEYSIZE,noncesize=NONCESIZE):
    # pysodium silently computes the hash of an empty string if input is not bytes, so check for
    # and catch that.
    if isinstance(ctx, (str,)):
      ctx = ctx.encode('utf-8')
    if isinstance(salt, (str,)):
      salt = salt.encode('utf-8')
    if (ctx is None or not isinstance(ctx,(bytes,bytearray))):
      ctx = self.__ctx
    if (salt is None or not isinstance(salt,(bytes,bytearray))):
      salt = self.__salt
    if (not isinstance(msg,(bytes,bytearray))):
      raise KafkaCryptoGeneratorError("Message is not bytes!")
    keynonce = pysodium.crypto_generichash_blake2b_salt_personal(msg,key=self.__secret,salt=salt,personal=ctx,outlen=keysize+noncesize)
    self.__salt = (int.from_bytes(self.__salt, byteorder='little', signed=False)+1).to_bytes(self.SALTSIZE, byteorder='little', signed=False)
    return (keynonce[0:keysize], keynonce[-noncesize:])

  def salt(self):
    return self.__salt

  @staticmethod
  def get_key_value_generators(secret):
    return (KeyGenerator(secret=secret,ctx=b'key'+(b'\x00'*13)), KeyGenerator(secret=secret,ctx=b'value'+(b'\x00'*11)))
