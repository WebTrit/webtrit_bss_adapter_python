from dataclasses import dataclass

@dataclass
class Attr:
    name: str
    type: str = type("")
    expected: object = None
    mandatory: bool = False

def verify_attribute_in_json(attr: Attr, attr_dict: dict):
    if attr.mandatory:
        # is present if it should be
        assert attr.name in attr_dict
        assert attr_dict[attr.name] is not None  # not empty
    if attr.name in attr_dict and attr_dict[attr.name] is not None:
        verify_attribute_value(attr, attr_dict[attr.name])

def verify_attribute_value(attr: Attr, value):
    assert isinstance(value, attr.type)  # same type
    if attr.expected:
        expected_value = attr.expected() if callable(attr.expected) else attr.expected
        assert value == expected_value
