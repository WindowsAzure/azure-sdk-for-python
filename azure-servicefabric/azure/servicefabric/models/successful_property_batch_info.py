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

from .property_batch_info import PropertyBatchInfo


class SuccessfulPropertyBatchInfo(PropertyBatchInfo):
    """Derived from PropertyBatchInfo. Represents the property batch succeeding.
    Contains the results of any "Get" operations in the batch.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param properties: A map containing the properties that were requested
     through any "Get" property batch operations. The key represents the index
     of the "Get" operation in the original request, in string form. The value
     is the property. If a property is not found, it will not be in the map.
    :type properties: dict[str, ~azure.servicefabric.models.PropertyInfo]
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
        'properties': {'key': 'Properties', 'type': '{PropertyInfo}'},
    }

    def __init__(self, **kwargs):
        super(SuccessfulPropertyBatchInfo, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
        self.kind = 'Successful'
