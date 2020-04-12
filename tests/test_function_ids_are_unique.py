from compal.functions import GetFunction, SetFunction


def validate_key_value_object(key_value_object):
    known_keys = set()
    known_values = set()

    for attr, value in vars(GetFunction).items():
        assert attr not in known_keys
        assert value not in known_values

        known_keys.add(attr)
        known_values.add(value)


def test_get_functions_are_unique():
    validate_key_value_object(GetFunction)


def test_set_functions_are_unique():
    validate_key_value_object(SetFunction)
