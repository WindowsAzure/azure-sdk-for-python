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


class PropertyBatchDescriptionList(Model):
    """Describes a list of property batch operations to be executed. Either all or
    none of the operations will be committed.

    :param operations: A list of the property batch operations to be executed.
    :type operations: list of :class:`PropertyBatchOperation
     <azure.servicefabric.models.PropertyBatchOperation>`
    """

    _attribute_map = {
        'operations': {'key': 'Operations', 'type': '[PropertyBatchOperation]'},
    }

    def __init__(self, operations=None):
        self.operations = operations
