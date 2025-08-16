#import json
import pickle
import inspect
import sys
from abc import ABC, abstractmethod
from dataclasses import is_dataclass, asdict
from pydantic import BaseModel
import orjson

from bss.types import Serialiazable

base_serializer_class = Serialiazable

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
            if hasattr(constructor, 'model_validate_json') and SerializerBase.FULL_JSON in params:
                return constructor.model_validate_json(params[SerializerBase.FULL_JSON])

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
        elif hasattr(obj, 'model_dump') and callable(getattr(obj, 'model_dump')):
            data = { key: cls.obj_to_dict(val)
                      for key, val in obj.model_dump().items() }
            return data
        raise ValueError(f"Cannot convert object of type {type(obj)} to dict")
                         
    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""

        obj_data = {}
        # Get the original field values, not the dumped values
        for field_name, field_info in obj.model_fields.items():
            if field_name in obj.model_dump():
                val = getattr(obj, field_name)
                if cls.is_scalar(val):
                    obj_data[field_name] = val
                elif isinstance(val, Serialiazable):
                    # Recursively pack nested objects
                    obj_data[field_name] = cls.pack(val)
                elif isinstance(val, list):
                    # Handle lists of objects
                    obj_data[field_name] = [
                        cls.pack(item) if isinstance(item, Serialiazable) else item
                        for item in val
                    ]
                else:
                    # For other types, use orjson
                    obj_data[field_name] = orjson.dumps(val).decode('utf-8')
        
        # other attributes are for browsing / searching objects, this one
        # to re-store the object
        obj_data[SerializerBase.FULL_JSON] = obj.model_dump_json()
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


class SerializerPydanticLight(SerializerBase):
    """Store/recall pydantic BaseModel objects from a DB as individual Firestore attributes"""

    ID = "BaseModelLight"

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
        elif hasattr(obj, 'model_dump') and callable(getattr(obj, 'model_dump')):
            data = { key: cls.obj_to_dict(val)
                      for key, val in obj.model_dump().items() }
            return data
        raise ValueError(f"Cannot convert object of type {type(obj)} to dict")
                         
    @classmethod
    def pack(cls, obj: object) -> dict:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_data = {}
        # Get the original field values, not the dumped values
        for field_name, field_info in obj.model_fields.items():
            if field_name in obj.model_dump():
                val = getattr(obj, field_name)
                if cls.is_scalar(val):
                    obj_data[field_name] = val
                elif isinstance(val, Serialiazable):
                    # For nested Pydantic objects, always use light serializer to maintain consistency
                    # This ensures we don't get the _*json*_ field and maintain the "light" approach
                    obj_data[field_name] = cls.pack(val)
                elif isinstance(val, list):
                    # Handle lists of objects
                    obj_data[field_name] = []
                    for item in val:
                        if isinstance(item, Serialiazable):
                            # Always use light serializer for nested objects to maintain consistency
                            obj_data[field_name].append(cls.pack(item))
                        else:
                            obj_data[field_name].append(item)
                else:
                    # For other types, use orjson
                    obj_data[field_name] = orjson.dumps(val).decode('utf-8')
        
        return obj_data | {
                SerializerBase.OBJ_TYPE: type(obj).__name__,
                SerializerBase.OBJ_PACKER: SerializerPydanticLight.ID,
            }

    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_type = d.pop(SerializerBase.OBJ_TYPE, "None")
        d.pop(SerializerBase.OBJ_PACKER, None)
        
        # Process nested objects before creating the main object
        processed_data = {}
        for key, val in d.items():
            if isinstance(val, dict) and SerializerBase.OBJ_TYPE in val:
                # This is a serialized object, unpack it
                processed_data[key] = Serializer.unpack(val)
            elif isinstance(val, list):
                # Process list items
                processed_data[key] = [
                    Serializer.unpack(item) if isinstance(item, dict) and SerializerBase.OBJ_TYPE in item else item
                    for item in val
                ]
            elif isinstance(val, str):
                # Try to parse JSON strings back to their original types
                try:
                    # Handle 'null' strings
                    if val == 'null':
                        processed_data[key] = None
                        continue
                    
                    # Check if it looks like a JSON string
                    if val.startswith('"') and val.endswith('"'):
                        # This might be a datetime string
                        try:
                            from datetime import datetime
                            # Remove quotes and try to parse as datetime
                            clean_val = val.strip('"')
                            if 'T' in clean_val and ('-' in clean_val or ':' in clean_val):
                                # Try to parse as ISO datetime
                                parsed_datetime = datetime.fromisoformat(clean_val.replace('Z', '+00:00'))
                                processed_data[key] = parsed_datetime
                                continue
                        except (ValueError, TypeError):
                            pass
                        
                        # Try to parse as regular JSON
                        try:
                            import orjson
                            parsed_json = orjson.loads(val)
                            processed_data[key] = parsed_json
                            continue
                        except (ValueError, TypeError, orjson.JSONDecodeError):
                            pass
                    
                    # If it's a JSON object/dict/array
                    if val.startswith('{') or val.startswith('['):
                        try:
                            import orjson
                            parsed_json = orjson.loads(val)
                            processed_data[key] = parsed_json
                            continue
                        except (ValueError, TypeError, orjson.JSONDecodeError):
                            pass
                    
                    # If none of the above worked, keep as string
                    processed_data[key] = val
                except Exception:
                    # If anything goes wrong, keep the original value
                    processed_data[key] = val
            else:
                processed_data[key] = val
        
        return cls.produce_object(obj_type, processed_data)


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
        elif isinstance(obj, base_serializer_class):
            # Check if the object prefers the light serializer
            if True:
                serializer = SerializerPydanticLight
            else:
                # old one
                serializer = SerializerPydantic
        else:
            # use pickle to serialize a complex object
            serializer = SerializerObject
        return serializer.pack(obj)



    @classmethod
    def unpack(cls, d: dict) -> object:
        """Convert the object to a format that can be stored as
        document in NoSQL DB"""
        obj_type = d.get(SerializerBase.OBJ_PACKER, None)
        match obj_type:
            case SerializerScalar.ID:
                serializer = SerializerScalar
            case SerializerPydantic.ID:
                serializer = SerializerPydantic
            case SerializerPydanticLight.ID:
                serializer = SerializerPydanticLight
            case SerializerDataclass.ID:
                serializer = SerializerDataclass
            case SerializerDict.ID:
                serializer = SerializerDict
            case SerializerObject.ID:
                serializer = SerializerObject
            case _:
                # fall-back to dictionary
                serializer = SerializerDict
        # remove the packer attribute and pass the rest to the serializer
        copy_of_d = { k:v for k,v in d.items() if k != SerializerBase.OBJ_PACKER }
        return serializer.unpack(copy_of_d)

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
        str_attr_optional: Optional[str]
        int_attr: int
        float_attr: float
        date_attr: datetime
        list_attr: List[Any]
        obj_attr: SubObj

    class Test1Light(Serialiazable):
        use_light_serializer = True  # This will use SerializerPydanticLight
        str_attr: str
        int_attr: int
        nested_obj: SubObj  # Test nested object handling

    sub = SubObj(some_attr='Heavy metal')
    x = Test1(str_attr = "ABC", int_attr=42, float_attr=3.14,
            date_attr=datetime.now(),
            list_attr=[  sub, 'Manowar'],
            obj_attr=sub)
    print(x.model_dump_json())
    assert (packed:=pack(x)) 
    assert (unpacked:=unpack(packed))
    assert unpacked == x
    
    # Test the new SerializerPydanticLight
    print("\nTesting SerializerPydanticLight:")
    x_light = Test1Light(str_attr="DEF", int_attr=123, nested_obj=sub)
    assert (packed_light:=pack(x_light))
    assert (unpacked_light:=unpack(packed_light))
    assert unpacked_light == x_light
    print("Light serializer test passed!")
    
    print("Done!")
