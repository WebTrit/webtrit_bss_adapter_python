import threading
import shelve
import logging
from bss.types import AppConfig

class TiedKeyValue():
    """Dict-like access to external database, similar to
    Perl's tied hash. This class works as a dictionary, but with
    locks for data changes, so it can be safely used in FastAPI apps.
    It is a base class for your sub-classes,
    which will implement the interface to the actual database.
    
    The constructor gets the configuration object, so the class
    can extract all required info from it."""
    def __init__(self, **kwargs):
        self._data = dict(**kwargs)
        self.lock = threading.Lock()

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, *args):
        if args:
            # called as x.get(key, default)
            return self._data.get(key, args[0])
        return self._data.get(key)

    def pop(self, key, *args):
        if args:
            # called as x.get(key, default)
            return self._data.pop(key, args[0])
        return self._data.pop(key)
     
    def __setitem__(self, key, value):
        with self.lock:
            self._data[key] = value

    def __delitem__(self, key):
        with self.lock:
            del self._data[key]

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)   
    
class FileStoredKeyValue(TiedKeyValue):
    """Store data in a file, using shelve module."""
    def __init__(self, file_name: str, **kwargs):
        super().__init__(**kwargs)
        #logging.debug(f"Using file {file_name} for storage")
        self._data = shelve.open(file_name)


