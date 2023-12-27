import threading
import shelve
import logging


class TiedKeyValue:
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
        """Internal method, called when accessing the data as my_dict[key]"""
        return self._data[key]

    def get(self, key, *args):
        """Override the standard dict.get() method"""
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
        """Internal method, called when setting a value to a dict key,
        for instance my_dict[key] = value"""
        with self.lock:
            self._data[key] = value

    def __delitem__(self, key):
        """Internal method, called when the code does
        del my_dict[key]"""
        with self.lock:
            del self._data[key]

    def __contains__(self, key):
        """Internal method, called when the code does a check like
        key in my_dict"""
        return key in self._data

    def __iter__(self):
        """Internal method, called when the code has a construct like
        for key in obj"""
        return iter(self._data)

    def __len__(self):
        """Internal method, called when the code has a construct like
        if len(my_obj) > 0: """
        return len(self._data)

    def keys(self):
        return self._data.keys()

    def items(self):
        return self._data.items()

    def values(self):
        return self._data.items()

class FileStoredKeyValue(TiedKeyValue):
    """Store data in a file, using shelve module."""

    def __init__(self, file_name: str, **kwargs):
        super().__init__(**kwargs)
        self._data = shelve.open(file_name)
