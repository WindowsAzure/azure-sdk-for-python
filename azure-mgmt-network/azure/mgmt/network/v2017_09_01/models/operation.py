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


class Operation(Model):
    """Network REST API operation definition.

    :param name: Operation name: {provider}/{resource}/{operation}
    :type name: str
    :param display: Display metadata associated with the operation.
    :type display: ~azure.mgmt.network.v2017_09_01.models.OperationDisplay
    :param origin: Origin of the operation.
    :type origin: str
    :param service_specification: Specification of the service.
    :type service_specification:
     ~azure.mgmt.network.v2017_09_01.models.OperationPropertiesFormatServiceSpecification
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'service_specification': {'key': 'properties.serviceSpecification', 'type': 'OperationPropertiesFormatServiceSpecification'},
    }

    def __init__(self, name=None, display=None, origin=None, service_specification=None):
        super(Operation, self).__init__()
        self.name = name
        self.display = display
        self.origin = origin
        self.service_specification = service_specification
