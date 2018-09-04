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

from .property_batch_operation import PropertyBatchOperation


class PutPropertyBatchOperation(PropertyBatchOperation):
    """Puts the specified property under the specified name.
    Note that if one PropertyBatchOperation in a PropertyBatch fails,
    the entire batch fails and cannot be committed in a transactional manner.

    All required parameters must be populated in order to send to Azure.

    :param property_name: Required. The name of the Service Fabric property.
    :type property_name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param value: Required. Describes a Service Fabric property value.
    :type value: ~azure.servicefabric.models.PropertyValue
    :param custom_type_id: The property's custom type ID. Using this property,
     the user is able to tag the type of the value of the property.
    :type custom_type_id: str
    """

    _validation = {
        'property_name': {'required': True},
        'kind': {'required': True},
        'value': {'required': True},
    }

    _attribute_map = {
        'property_name': {'key': 'PropertyName', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'value': {'key': 'Value', 'type': 'PropertyValue'},
        'custom_type_id': {'key': 'CustomTypeId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PutPropertyBatchOperation, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.custom_type_id = kwargs.get('custom_type_id', None)
        self.kind = 'Put'
