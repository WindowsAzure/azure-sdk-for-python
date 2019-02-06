# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DatasetStorageFormat(Model):
    """The format definition of a storage.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ParquetFormat, OrcFormat, AvroFormat, JsonFormat,
    TextFormat

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param serializer: Serializer. Type: string (or Expression with resultType
     string).
    :type serializer: object
    :param deserializer: Deserializer. Type: string (or Expression with
     resultType string).
    :type deserializer: object
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'serializer': {'key': 'serializer', 'type': 'object'},
        'deserializer': {'key': 'deserializer', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'ParquetFormat': 'ParquetFormat', 'OrcFormat': 'OrcFormat', 'AvroFormat': 'AvroFormat', 'JsonFormat': 'JsonFormat', 'TextFormat': 'TextFormat'}
    }

    def __init__(self, **kwargs):
        super(DatasetStorageFormat, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.serializer = kwargs.get('serializer', None)
        self.deserializer = kwargs.get('deserializer', None)
        self.type = None
