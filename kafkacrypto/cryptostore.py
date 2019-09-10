from time import time
from configparser import ConfigParser
import traceback
import pysodium
import msgpack
import logging
from kafkacrypto.exceptions import KafkaCryptoStoreError
from kafkacrypto.utils import str_encode, str_decode

class CryptoStore(object):
  """Class utilizing file-backed location for storage of non-secret crypto
     configuration parameters.

  Keyword Arguments:
             nodeID (str): Node ID
          file (str,file): Filename or File IO object for storing crypto info.
                           Must be seekable, with read/write permission,
                           honor sync requests, and only be written by one
                           instance of this class at a time.
  """
  #
  # Per instance, defined in init
  #    __nodeID: Node ID
  #      __file: File object
  #    __config: Live configuration parser object representing the data
  #              in the configuration file
  #
  def __init__(self, nodeID, file):
    self._logger = logging.getLogger(__name__)
    if (not isinstance(nodeID, (str)) or len(nodeID) < 1):
      raise KafkaCryptoStoreError("Node ID " + str(nodeID) + " not a string or not specified!")
    if (isinstance(file, (str))):
      file = open(file, 'r+')
    self.__nodeID = nodeID
    self.__cryptokey = None
    self.__file = file
    self.__file.seek(0,0)
    self.__config = ConfigParser(delimiters=(':'),comment_prefixes=(';'))
    self.__config.read_file(self.__file)
    if not (nodeID in self.__config):
      self.__config[nodeID] = {}

  def load_section(self, section):
    rv = None
    if section is None:
      section = self.__nodeID
    else:
      section = self.__nodeID + "-" + section
    if section in self.__config:
      self._logger.debug("Attempting to load section %s", section)
      rv = {}
      for key in self.__config[section]:
        rv[str_decode(key)] = str_decode(self.__config[section][key])
    return rv

  def load_value(self, name, section=None):
    if section is None:
      section =	self.__nodeID
    else:
      section =	self.__nodeID + "-" + section
    section = str_encode(section)
    self._logger.debug("Attempting to load value for %s from %s", name, section)
    rv = None
    if section in self.__config and name in self.__config[section]:
      rv = str_decode(self.__config[section][str_encode(name)])
    self._logger.debug("Loaded name=%s, value=%s from %s", name, rv, section)
    return rv

  def store_value(self, name, value, section=None):
    if section is None:
      section =	self.__nodeID
    else:
      section =	self.__nodeID + "-" + section
    section = str_encode(section)
    self._logger.debug("Storing name=%s, value=%s in %s", name, value, section)
    if not (section in self.__config):
      self.__config[section] = {}
    self.__config[section][str_encode(name)] = str_encode(value)
    self.__file.seek(0,0)
    self.__config.write(self.__file)
    self.__file.flush()
    self.__file.truncate()
    self.__file.flush()
    self._logger.debug("Successfully stored.")

  def set_cryptokey(self, cryptokey):
    self.__cryptokey = cryptokey

  def load_opaque_value(self, name, section=None):
    rv = self.load_value(name,section)
    if rv!= None:
      return self.__cryptokey.unwrap_opaque(rv)
    else:
      return None

  def store_opaque_value(self, name, value, section=None):
    value = self.__cryptokey.wrap_opaque(value)
    self.store_value(name, value, section)

