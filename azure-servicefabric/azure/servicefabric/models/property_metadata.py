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


class PropertyMetadata(Model):
    """The metadata associated with a property, including the property's name.

    :param type_id: The kind of property, determined by the type of data.
     Following are the possible values. Possible values include: 'Invalid',
     'Binary', 'Int64', 'Double', 'String', 'Guid'
    :type type_id: str or ~azure.servicefabric.models.PropertyValueKind
    :param custom_type_id: The property's custom type id.
    :type custom_type_id: str
    :param parent: The name of the parent Service Fabric Name for the
     property. It could be thought of as the namespace/table under which the
     property exists.
    :type parent: str
    :param size_in_bytes: The length of the serialized property value.
    :type size_in_bytes: int
    :param last_modified_utc_timestamp: Represents when the Property was last
     modified. Only write operations will cause this field to be updated.
    :type last_modified_utc_timestamp: datetime
    :param sequence_number: The version of the property. Every time a property
     is modified, its sequence number is increased.
    :type sequence_number: str
    """

    _attribute_map = {
        'type_id': {'key': 'TypeId', 'type': 'str'},
        'custom_type_id': {'key': 'CustomTypeId', 'type': 'str'},
        'parent': {'key': 'Parent', 'type': 'str'},
        'size_in_bytes': {'key': 'SizeInBytes', 'type': 'int'},
        'last_modified_utc_timestamp': {'key': 'LastModifiedUtcTimestamp', 'type': 'iso-8601'},
        'sequence_number': {'key': 'SequenceNumber', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PropertyMetadata, self).__init__(**kwargs)
        self.type_id = kwargs.get('type_id', None)
        self.custom_type_id = kwargs.get('custom_type_id', None)
        self.parent = kwargs.get('parent', None)
        self.size_in_bytes = kwargs.get('size_in_bytes', None)
        self.last_modified_utc_timestamp = kwargs.get('last_modified_utc_timestamp', None)
        self.sequence_number = kwargs.get('sequence_number', None)
