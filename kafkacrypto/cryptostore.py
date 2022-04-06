from time import time
from threading import Lock
from configparser import ConfigParser
from os import path
from binascii import unhexlify
import pysodium
import msgpack
import logging
from kafkacrypto.exceptions import KafkaCryptoStoreError
from kafkacrypto.utils import str_encode, str_decode, atomic_open

class CryptoStore(object):
  """Class utilizing file-backed location for storage of non-secret crypto
     configuration parameters.

  Keyword Arguments:
             nodeID (str): Node ID
          file (str,file): Filename or File IO object for storing crypto info.
                           Must be seekable, with read/write permission,
                           honor sync requests, and only be written by one
                           instance of this class at a time. If a File IO object,
                           writes and truncates should not be persisted until
                           flush is called (to form a single large atomic op).
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
    self.__lock = Lock()
    self.__keylock = Lock()

    self._need_init = False
    if (file is None) and isinstance(nodeID, (str)) and len(nodeID) > 0:
      file = nodeID + ".config"
    if (isinstance(file, (str))):
      if (not path.exists(file) and isinstance(nodeID, (str))):
        with open(file, "w") as f:
          f.write("[DEFAULT]\n")
        self._need_init = True
      file = atomic_open(file,'r+')
    self.__cryptokey = None
    self.__file = file
    self.__file.seek(0,0)
    self.__config = ConfigParser(delimiters=(':'),comment_prefixes=(';'))
    # enable keys to be stored base64 too by making keys case sensitive. Other functions here
    # then restore the expected case insensitive behavior for standard keys
    self.__config.optionxform = str
    self.__config.read_file(self.__file)
    nodeIDfile = self.__config['DEFAULT'].get('node_id', None)
    if (not isinstance(nodeID, (str)) or len(nodeID) < 1):
      if (isinstance(nodeIDfile, (str)) and len(nodeIDfile) > 0):
        nodeID = nodeIDfile
      else:
        raise KafkaCryptoStoreError("Node ID " + str(nodeID) + " not a string or not specified!")
    else:
      if (isinstance(nodeIDfile, (str)) and len(nodeIDfile) > 0 and nodeIDfile != nodeID):
        raise KafkaCryptoStoreError("Node ID mismatch in file " + nodeIDfile + " versus " + str(nodeID))
      else:
        self._nodeID = nodeID
        self.store_value("node_id", nodeID, section="DEFAULT", rawSection=True)
    self._nodeID = nodeID

    if self._need_init:
      self.__init_cryptostore(file, nodeID)

  def close(self):
    with self.__lock:
      try:
        self.__file.close()
      except:
        pass
      finally:
        self.__file = None
      with self.__keylock:
        self.__cryptokey = None
      self.__keylock = None
    self.__lock = None

  def get_nodeID(self):
    # read-only, no lock needed
    return self._nodeID

  def load_section(self, section, defaults=True):
    # need lock
    with self.__lock:
      rv = None
      if section is None:
        section = self._nodeID
      else:
        section = self._nodeID + "-" + section
      if section in self.__config:
        self._logger.debug("Attempting to load section %s", section)
        rv = {}
        for key in self.__config[section]:
          rv[str_decode(key,iskey=True)] = str_decode(self.__config[section][key])
      elif defaults:
        self._logger.debug("Loading defaults for section %s", section)
        rv = {}
        for key in self.__config['DEFAULT']:
          rv[str_decode(key,iskey=True)] = str_decode(self.__config['DEFAULT'][key])
      if not defaults and rv!=None:
        for key in self.__config['DEFAULT']:
          if str_decode(key,iskey=True) in rv and str_decode(self.__config['DEFAULT'][key]) == rv[str_decode(key,iskey=True)]:
            rv.pop(str_decode(key,iskey=True), None)
    return rv

  def load_value(self, name, section=None, default=None):
    with self.__lock:
      if section is None:
        section = self._nodeID
      else:
        section = self._nodeID + "-" + section
      section = str_encode(section)
      self._logger.debug("Attempting to load value for %s from %s", name, section)
      rv = None
      if section in self.__config and str_encode(name,iskey=True) in self.__config[section]:
        rv = str_decode(self.__config[section][str_encode(name,iskey=True)])
      elif str_encode(name,iskey=True) in self.__config['DEFAULT']:
        rv = str_decode(self.__config['DEFAULT'][str_encode(name,iskey=True)])
      else:
        rv = default
      self._logger.debug("Loaded name=%s, value=%s from %s", name, rv, section)
    return rv

  def store_value(self, name, value, section=None, rawSection=False):
    self.store_values([[name,value]], section=section, rawSection=rawSection)

  def store_values(self, namevals, section=None, rawSection=False):
    if len(namevals) < 1:
      self._logger.debug("store_values called with no parameters.")
      return
    if section is None:
      section = self._nodeID
    elif not rawSection:
      section = self._nodeID + "-" + section
    section = str_encode(section)
    with self.__lock:
      if not (section in self.__config):
        self.__config[section] = {}
      for [name, value] in namevals:
        self._logger.debug("Storing name=%s, value=%s in %s", name, value, section)
        if value!=None:
          self.__config[section][str_encode(name,iskey=True)] = str_encode(value)
        else:
          self.__config[section].pop(str_encode(name,iskey=True),None)
      self.__file.seek(0,0)
      self.__config.write(self.__file)
      self.__file.truncate()
      self.__file.flush()
      self._logger.debug("Successfully stored.")

  def set_cryptokey(self, cryptokey):
    with self.__keylock:
      self.__cryptokey = cryptokey

  def load_opaque_value(self, name, section=None, default=None):
    with self.__keylock:
      rv = self.load_value(name,section,default)
      if rv!= None:
        return self.__cryptokey.unwrap_opaque(rv)
      else:
        return None

  def store_opaque_value(self, name, value, section=None):
    with self.__keylock:
      value = self.__cryptokey.wrap_opaque(value)
      self.store_value(name, value, section)

  def __init_cryptostore(self, file, nodeID):
    self._logger.warning("Initializing new CryptoStore file=%s, nodeID=%s.", file, nodeID)
    self.store_value('test','test')
    self.store_value('test',None)
    self.store_value('MGMT_LONG_KEYINDEX',True)
    self._logger.warning("  Including a default/temporary root of trust. Once proper access is provisioned, this root of trust should be removed or distrusted.");
    self.store_value('temporary',msgpack.packb([0,msgpack.packb([['pathlen',2]], use_bin_type=True),unhexlify(b'1a13b0aecdd6751c7dfa43e43284326ad01dbc20a8a00b1566092ab0a542620f')], use_bin_type=True), section='allowlist')
    self.store_value('test','test',section='denylist')
    self.store_value('test',None,section='denylist')
    self.store_value('test','test',section='crypto')
    self.store_value('test',None,section='crypto')
    self._logger.warning("  CryptoStore Initialized.")
