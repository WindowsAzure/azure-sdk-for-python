# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class StorageAccountCheckNameAvailabilityParameters(Model):
    """StorageAccountCheckNameAvailabilityParameters

    :param name:
    :type name: str
    :param type:  Default value: "Microsoft.Storage/storageAccounts" .
    :type type: str
    """ 

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, name, type="Microsoft.Storage/storageAccounts"):
        self.name = name
        self.type = type
