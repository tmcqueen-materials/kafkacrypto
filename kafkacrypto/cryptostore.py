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
  #    _nodeID: Node ID
  #      __file: File object
  #    __config: Live configuration parser object representing the data
  #              in the configuration file
  #
  def __init__(self, nodeID=None, file=None):
    self._logger = logging.getLogger(__name__)
    if (isinstance(file, (str))):
      file = open(file, 'r+')
    self.__cryptokey = None
    self.__file = file
    self.__file.seek(0,0)
    self.__config = ConfigParser(delimiters=(':'),comment_prefixes=(';'))
    self.__config.read_file(self.__file)
    nodeIDfile = self.__config['DEFAULT'].get('node_id', None)
    if (not isinstance(nodeID, (str)) or len(nodeID) < 1):
      if (isinstance(nodeIDfile, (str)) and len(nodeIDfile) > 0):
        nodeID = nodeIDfile
      else:
        raise KafkaCryptoStoreError("Node ID " + str(nodeID) + " not a string or not specified!")
    elif (isinstance(nodeIDfile, (str))	and len(nodeIDfile) > 0 and nodeIDfile != nodeID):
      raise KafkaCryptoStoreError("Node ID mismatch in file " + nodeIDfile + " versus " + str(nodeID))
    self._nodeID = nodeID

    if not (nodeID in self.__config):
      self.__config[nodeID] = {}

  def load_section(self, section, defaults=True):
    rv = None
    if section is None:
      section = self._nodeID
    else:
      section = self._nodeID + "-" + section
    if section in self.__config:
      self._logger.debug("Attempting to load section %s", section)
      rv = {}
      for key in self.__config[section]:
        rv[str_decode(key)] = str_decode(self.__config[section][key])
    elif defaults:
      self._logger.debug("Loading defaults for section %s", section)
      rv = {}
      for key in self.__config['DEFAULT']:
        rv[str_decode(key)] = str_decode(self.__config['DEFAULT'][key])
    if not defaults and rv!=None:
      for key in self.__config['DEFAULT']:
        if str_decode(key) in rv and str_decode(self.__config['DEFAULT'][key]) == rv[str_decode(key)]:
          rv.pop(str_decode(key), None)
    return rv

  def load_value(self, name, section=None, default=None):
    if section is None:
      section =	self._nodeID
    else:
      section =	self._nodeID + "-" + section
    section = str_encode(section)
    self._logger.debug("Attempting to load value for %s from %s", name, section)
    rv = None
    if section in self.__config and name in self.__config[section]:
      rv = str_decode(self.__config[section][str_encode(name)])
    else:
      rv = default
    self._logger.debug("Loaded name=%s, value=%s from %s", name, rv, section)
    return rv

  def store_value(self, name, value, section=None):
    if section is None:
      section =	self._nodeID
    else:
      section =	self._nodeID + "-" + section
    section = str_encode(section)
    self._logger.debug("Storing name=%s, value=%s in %s", name, value, section)
    if not (section in self.__config):
      self.__config[section] = {}
    if value!=None:
      self.__config[section][str_encode(name)] = str_encode(value)
    else:
      self.__config[section].pop(str_encode(name),None)
    self.__file.seek(0,0)
    self.__config.write(self.__file)
    self.__file.flush()
    self.__file.truncate()
    self.__file.flush()
    self._logger.debug("Successfully stored.")

  def set_cryptokey(self, cryptokey):
    self.__cryptokey = cryptokey

  def load_opaque_value(self, name, section=None, default=None):
    rv = self.load_value(name,section,default)
    if rv!= None:
      return self.__cryptokey.unwrap_opaque(rv)
    else:
      return None

  def store_opaque_value(self, name, value, section=None):
    value = self.__cryptokey.wrap_opaque(value)
    self.store_value(name, value, section)

