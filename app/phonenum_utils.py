from phonenumbers import (NumberParseException, PhoneNumberFormat, PhoneNumberType,
                          parse as parse_phone_number, is_valid_number, format_number)

class PhonenumPrefixSet:
    def __init__(self, prefixes: str = ""):
        """
        Initializes the PhonenumPrefixSet with optional comma-separated prefixes.

        Args:
            prefixes (str): A string of comma-separated prefixes, e.g., "34,106,1".
        """
        self.prefixes = set()
        if prefixes:
            self._add_prefixes_from_string(prefixes)

    def _add_prefixes_from_string(self, prefixes: str):
        """
        Adds prefixes from a comma-separated string.

        Args:
            prefixes (str): A string of comma-separated prefixes.
        """
        for prefix in prefixes.split(","):
            self.add_prefix(prefix.strip())

    def add_prefix(self, prefix: str):
        """
        Adds a single phone prefix to the set.

        Args:
            prefix (str): The phone prefix, e.g., "106" or "+34".
        """
        if not prefix.startswith("+"):
            prefix = f"+{prefix}"  # Automatically add '+' if missing
        self.prefixes.add(prefix)

    def matches(self, phone_number: str) -> str:
        """
        Checks if a given phone number matches one of the stored prefixes.

        Args:
            phone_number (str): The phone number to check, e.g., "+34123456789".

        Returns:
            str: The prefix that matches the phone number, or None if no match is found.
        """
        for prefix in self.prefixes:
            if phone_number.startswith(prefix):
                return prefix
        return None

    def __repr__(self):
        """
        Returns a string representation of the prefix set.
        """
        return f"PhonenumPrefixSet({sorted(self.prefixes)})"


def validate_phone_number(phone_number: str, default_region: str = "US") -> str:
    """
    Validates and formats a phone number to the E.164 format.
    
    Args:
        phone_number (str): The phone number to validate and format.
        default_region (str): The default region for parsing (if country code is missing).
    
    Returns:
        str: The formatted phone number in international format.
    
    Raises:
        ValueError: If the phone number is invalid.
    """
    try:
        # Parse the phone number
        parsed_number = parse_phone_number(phone_number, default_region)
        
        # Check if the number is valid
        if not is_valid_number(parsed_number):
            raise ValueError(f"Invalid phone number: {phone_number}")
        
        # Format the number to the E.164 format
        return format_number(parsed_number, PhoneNumberFormat.E164)
    except NumberParseException as e:
        raise ValueError(f"Error parsing phone number: {e}")
