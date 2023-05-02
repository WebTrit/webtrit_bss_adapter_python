import json
import pickle
import json
import inspect
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, is_dataclass, asdict


class SerializerBase(ABC):
    """Store/recall scalar objects (strings, numbers) in a NoSQL DB"""

    OBJ_TYPE = "_*object_type*_"
    OBJ_DATA = "_*object_data*_"
    OBJ_PACKER = "_*object_packer*_"
    OBJ_ID = '_*id*_'  # attribute to store object ID
    # constrcutors to product objects of a given class
    factories = {}

    # def __init__(self):
    #     self.
    @abstractmethod
    def pack(self, obj) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        pass

    @abstractmethod
    def unpack(self, d) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        pass

    @classmethod
    def structure(cls, obj_type: str, packer: str, value) -> dict:
        """Return the structure that contains object type and the data"""
        return {
            SerializerBase.OBJ_TYPE: obj_type,
            SerializerBase.OBJ_PACKER: packer,
            SerializerBase.OBJ_DATA: value,
        }

    @classmethod
    def find_object_factory(cls, obj_type: str) -> callable:
        """Return the class' constructor for an object of a given type.
        Goes through list of loaded modules and looks it up."""
        for module in list(sys.modules.values()):
            try:
                if obj_type in dir(module):
                    class_obj = getattr(module, obj_type)
                    if inspect.isclass(class_obj):
                        return class_obj
            except ImportError:
                pass
        return None

    @classmethod
    def get_object_factory(cls, obj_type: str) -> callable:
        """Return the factory to produce an object of a given type
        and cache the result for future use."""
        if obj_type in SerializerBase.factories:
            return SerializerBase.factories[obj_type]

        # attempt to find and store
        if (constructor := cls.find_object_factory(obj_type)) is not None:
            SerializerBase.factories[obj_type] = constructor
            return constructor

        return None

    @classmethod
    def produce_object(cls, obj_type: str, params: dict) -> object:
        """Dynamically produce an object of a given type"""
        if (constructor := cls.get_object_factory(obj_type)) is not None:
            return constructor(**params)
        raise ValueError(f"Cannot produce object of type {obj_type}")


class SerializerScalar(SerializerBase):
    """Store/recall scalar objects (strings, numbers) from a DB"""

    OBJ_TYPE = "scalar"
    ID = "scalar"

    @classmethod
    def pack(cls, obj) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        return cls.structure(SerializerScalar.OBJ_TYPE, SerializerScalar.ID, obj)

    @classmethod
    def unpack(cls, d) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        return d.get(SerializerBase.OBJ_DATA, None)


class SerializerDict(SerializerBase):
    """Store/recall scalar objects (strings, numbers) from a DB"""

    OBJ_TYPE = "dict"
    ID = "dict"

    @classmethod
    def pack(cls, obj) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        return obj | {
            SerializerBase.OBJ_TYPE: type(obj).__name__,
            SerializerBase.OBJ_PACKER: SerializerDict.ID,
        }

    @classmethod
    def unpack(cls, d) -> object:
        """Convert the data from the format stored in NoSQL DB to a dict"""
        d.pop(SerializerBase.OBJ_TYPE, None)
        d.pop(SerializerBase.OBJ_PACKER, None)
        d.pop(SerializerBase.OBJ_ID, None)
        return d


class SerializerDataclass(SerializerBase):
    """Store/recall scalar objects (strings, numbers) from a DB"""

    ID = "Dataclass"

    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        return asdict(obj) | {
            SerializerBase.OBJ_TYPE: type(obj).__name__,
            SerializerBase.OBJ_PACKER: SerializerDataclass.ID,
        }

    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_type = d.pop(SerializerBase.OBJ_TYPE, "None")
        d.pop(SerializerBase.OBJ_PACKER, None)
        d.pop(SerializerBase.OBJ_ID, None)
        # TODO: fix this. now it is just a quick hack
        if 'User' in obj_type:
            d.pop('tenant_id', None)
        return cls.produce_object(obj_type, d)


class SerializerObject(SerializerBase):
    """Store/recall scalar objects (strings, numbers) from a DB"""

    ID = "ObjectPickle"

    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        return cls.structure(type(obj).__name__, SerializerObject.ID, pickle.dumps(obj))

    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        # obj_type = d.pop(SerializerBase.OBJ_TYPE, None)
        return pickle.loads(d.get(SerializerBase.OBJ_DATA, None))


class Serializer:
    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        if type(obj) in [str, int, float, bool]:
            serializer = SerializerScalar
        elif isinstance(obj, dict):
            serializer = SerializerDict
        elif is_dataclass(obj):
            serializer = SerializerDataclass
        else:
            # use pickle to serialize a complex object
            serializer = SerializerObject
        return serializer.pack(obj)

    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_type = d.pop(SerializerBase.OBJ_PACKER, None)
        match obj_type:
            case SerializerScalar.ID:
                serializer = SerializerScalar
            case SerializerDataclass.ID:
                serializer = SerializerDataclass
            case SerializerDict.ID:
                serializer = SerializerDict
            case SerializerObject.ID:
                serializer = SerializerObject
            case _:
                # fall-back to dictionary
                serializer = SerializerDict
        # d.pop()
        return serializer.unpack(d)
