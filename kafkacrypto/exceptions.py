#
# Copyright (c) 2018 Tyrel M. McQueen
#
class KafkaCryptoBaseError(Exception):
    """
    Base exception for all errors
    """

class KafkaCryptoStoreError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto store related errors
    """

class KafkaCryptoError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto related errors
    """

class KafkaCryptoUtilError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto utility related errors
    """

class KafkaCryptoControllerError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto controller related errors
    """

class KafkaCryptoSerializeError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto-serialize related errors
    """

class KafkaCryptoMessageError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto-message related errors
    """

class KafkaCryptoRatchetError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto-ratchet related errors
    """

class KafkaCryptoGeneratorError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto-generator related errors
    """

class KafkaCryptoWrapperError(KafkaCryptoBaseError):
    """
    Base exception for all kafka-crypto-wrapper related errors
    """

class KafkaCryptoChainServerError(KafkaCryptoBaseError):
    """
    Base exception for all chain-server related errors
    """

