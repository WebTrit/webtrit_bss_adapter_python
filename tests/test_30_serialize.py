import sys
import os
from datetime import datetime, timedelta
my_project_path = os.path.dirname(__file__ + '/app')
print(f"{my_project_path=}")
sys.path.append(os.getcwd() + '/app')


from bss.dbs.serializer import (
    Serializer, SerializerScalar,
    SerializerDataclass, SerializerObject)

def there_and_back2(obj, there: callable, back: callable):
    print(f"{obj=}")
    packed = there(obj)
    print(f"{packed=}")
    unpacked = back(packed)
    print(f"{unpacked=}")
    print("Identical" if obj == unpacked else "Different")

def there_and_back(obj, serializer: callable):
    return there_and_back2(obj, serializer.pack, serializer.unpack)


TEST_SCALARS = [1, 2.3, 'hello', b'hello']
for x in TEST_SCALARS:
    there_and_back(x, SerializerScalar)


from dataclasses import dataclass
@dataclass
class Person:
    firstname: str
    lastname: str
    age: int
    middlename: str = None
x = Person('John', 'Doe', 42)
there_and_back(x, SerializerDataclass)

@dataclass
class PersonWithDOB(Person):
    dob: datetime = None

y = PersonWithDOB('John', 'Doe', 42,
                  dob=datetime.now()-timedelta(days=42*365))

there_and_back(y, SerializerDataclass)


there_and_back(y, SerializerObject)

for x in TEST_SCALARS + [x, y]:
    there_and_back(x, Serializer)
