#import json
import pickle
import inspect
import sys
from abc import ABC, abstractmethod
from dataclasses import is_dataclass, asdict
from pydantic import BaseModel
import orjson

def orjson_dumps(v, *, default):
    return orjson.dumps(v, default=default).decode('utf-8')
 
class Serialiazable(BaseModel):
    """Object that can be converted into JSON structure"""
    def is_serializable(self) -> bool:
        return True
    
    class Config:
        json_loads = orjson.loads
        json_dumps = orjson_dumps


class SerializerBase(ABC):
    """Store/recall scalar objects (strings, numbers) in a NoSQL DB"""

    OBJ_TYPE = "_*object_type*_"
    OBJ_DATA = "_*object_data*_"
    OBJ_PACKER = "_*object_packer*_"
    FULL_JSON = "_*json*_"
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
            if hasattr(constructor, 'parse_raw') and SerializerBase.FULL_JSON in params:
                return constructor.parse_raw(params[SerializerBase.FULL_JSON])

            return constructor(**params)
        raise ValueError(f"Cannot produce object of type {obj_type}")
    @classmethod
    def is_scalar(cls, obj) -> bool:
        """Return True if the object is a scalar"""
        return isinstance(obj, (str, int, float, bool))

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
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        d.pop(SerializerBase.OBJ_TYPE, None)
        d.pop(SerializerBase.OBJ_PACKER, None)
        return d


class SerializerDataclass(SerializerBase):
    """Store/recall dataclass objects from a DB"""

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
        return cls.produce_object(obj_type, d)



class SerializerPydantic(SerializerBase):
    """Store/recall pydantic BaseModel objects from a DB"""

    ID = "BaseModel"

    @classmethod
    def obj_to_dict(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        if cls.is_scalar(obj):
            return obj
        if isinstance(obj, list):
            return [ cls.obj_to_dict(item) for item in obj ]
        elif isinstance(obj, dict):
            return { key: cls.obj_to_dict(val) for key, val in obj.items() }
        elif hasattr(obj, 'dict') and callable(getattr(obj, 'dict')):
            data = { key: cls.obj_to_dict(val)
                      for key, val in obj.dict().items() }
            return data
        raise ValueError(f"Cannot convert object of type {type(obj)} to dict")
                         
    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""

        obj_data = { key: val if cls.is_scalar(val) else 
                    cls.pack(val) if isinstance(val, Serialiazable)
                        else orjson.dumps(val).decode('utf-8') 
                    for key, val in obj.dict().items() }
        
        # other attributes are for browsing / searching objects, this one
        # to re-store the object
        obj_data[SerializerBase.FULL_JSON] = obj.json()
        return obj_data | {
                SerializerBase.OBJ_TYPE: type(obj).__name__,
                SerializerBase.OBJ_PACKER: SerializerPydantic.ID,
            }

    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_type = d.pop(SerializerBase.OBJ_TYPE, "None")
        d.pop(SerializerBase.OBJ_PACKER, None)
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
        if SerializerBase.is_scalar(obj):
            serializer = SerializerScalar
        elif isinstance(obj, dict):
            serializer = SerializerDict
        elif is_dataclass(obj):
            serializer = SerializerDataclass
        elif isinstance(obj, Serialiazable) or \
            (hasattr(obj, 'is_serializable') and obj.is_serializable()):
            serializer = SerializerPydantic
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
            case SerializerPydantic.ID:
                serializer = SerializerPydantic
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

def pack(obj: object) -> dict:
    """Convert the object to a format that can be stored as
    document in NoSQL DB"""
    return Serializer.pack(obj)

def unpack(d: dict) -> object:
    """Convert the object to a format that can be stored as
    document in NoSQL DB"""
    return Serializer.unpack(d)

if __name__ == "__main__":
    from pydantic import BaseModel
    from typing import List, Optional, Any
    from datetime import datetime

    class SubObj(Serialiazable):
        some_attr: Optional[str] = None

    class Test1(Serialiazable):
        str_attr: str
        str_w_default: Optional[str] = 'XYZ'
        int_attr: int
        float_attr: float
        date_attr: datetime
        list_attr: List[Any]
        obj_attr: SubObj

    sub = SubObj(some_attr='Heavy metal')
    x = Test1(str_attr = "ABC", int_attr=42, float_attr=3.14,
            date_attr=datetime.now(),
            list_attr=[  sub, 'Manowar'],
            obj_attr=sub)
    print(x.json())
    assert (packed:=pack(x)) 
    assert (unpacked:=unpack(packed))
    assert unpacked == x
