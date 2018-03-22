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

from .linked_integration_runtime_properties import LinkedIntegrationRuntimeProperties


class LinkedIntegrationRuntimeRbac(LinkedIntegrationRuntimeProperties):
    """The base definition of a secret type.

    All required parameters must be populated in order to send to Azure.

    :param authorization_type: Required. Constant filled by server.
    :type authorization_type: str
    :param resource_id: Required. The resource ID of the integration runtime
     to be shared.
    :type resource_id: str
    """

    _validation = {
        'authorization_type': {'required': True},
        'resource_id': {'required': True},
    }

    _attribute_map = {
        'authorization_type': {'key': 'authorizationType', 'type': 'str'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
    }

    def __init__(self, *, resource_id: str, **kwargs) -> None:
        super(LinkedIntegrationRuntimeRbac, self).__init__(, **kwargs)
        self.resource_id = resource_id
        self.authorization_type = 'RBAC'
