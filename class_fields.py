import datetime
from typing import Any, Dict, List, Union

UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field:
    """
    Field base class
    """

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.value = None
        self.name = None

    def __set__(self, instance, value):
        try:
            if self.required is True and value is None:
                raise ValueError("required not set")
            if self.nullable is False and not value:
                raise ValueError("empty require")
            if self.nullable is True and value is None:
                setattr(instance, self.name, None)
                return
            value = self.validate(value)
        except ValueError as e:
            raise ValueError("Field {}: {}".format(self.name[1:], str(e))) from e
        setattr(instance, self.name, value)

    def __set_name__(self, obj, name):
        self.name = "_" + name

    def __get__(self, instance, cls):
        return getattr(instance, self.name)

    def validate(self, value: Any) -> bool:
        return bool(value)


class CharField(Field):
    """
    Char field
    """

    def validate(self, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError('Field "{}" must be a string'.format(self.name))
        return value


class ArgumentsField(Field):
    """
    Arguments field
    """

    def validate(self, value: Dict[str, Any]) -> Dict[str, Any]:
        if not (isinstance(value, dict)):
            raise ValueError('Field "{}" must be a dict'.format(self.name))
        return value


class EmailField(CharField):
    """
    Email field
    """

    def validate(self, value: str) -> str:
        value = super().validate(value)
        if "@" not in value:
            raise ValueError('Field "{}" must be a valid email addr'.format(self.name))
        return value


class PhoneField(Field):
    """
    Phone field
    """

    def validate(self, value: Union[str, int]) -> str:
        if not (isinstance(value, (int, str))):
            raise ValueError("Wrong type")
        phone = str(value)
        if len(phone) != 11 or phone[0] != "7":
            raise ValueError('Field "{}" must be an integer, 11 chars len and starting with 7'.format(self.name))
        return phone


class DateField(CharField):
    """
    Date field
    """

    def validate(self, value):
        try:
            value = super().validate(value)
            date = datetime.datetime.strptime(value, "%d.%m.%Y").date()
            return date
        except ValueError:
            raise ValueError(
                'Field "{}" must be a string in format "DD.MM.YYYY"'.format(self.name)
            )


class BirthDayField(DateField):
    """
    Birthday field
    """

    MAX_AGE = 70

    def validate(self, value):
        date = super().validate(value)
        if datetime.date.today().year - date.year > self.MAX_AGE:
            raise ValueError(
                'Age more than {} years in field "{}"'.format(self.MAX_AGE, self.name)
            )
        return date


class GenderField(Field):
    """
    Gender field
    """

    def validate(self, val: int) -> int:
        possible_values = sorted(GENDERS.keys())
        err = 'Field "{}" must be an integer, one of {}'.format(
            self.name, ", ".join(str(i) for i in possible_values)
        )

        if not isinstance(val, int) or val not in possible_values:
            raise ValueError(err)

        return val


class ClientIDsField(Field):
    """
    Client IDs field
    """

    def validate(self, val: List[Any]) -> int:
        err = 'Field "{}" must be a list of positive integers'.format(self.name)
        if not isinstance(val, list) or not val:
            raise ValueError(err)

        for id_ in val:
            if not isinstance(id_, int) or id_ < 0:
                raise ValueError(err)

        return val
