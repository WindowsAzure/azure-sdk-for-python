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


class AdPrincipal(Model):
    """Active Directory Principal for subscription creation delegated permission.

    All required parameters must be populated in order to send to Azure.

    :param tenant_id: Required. Tenant id of the Principal. Must be the
     current tenant the caller is logged in to.
    :type tenant_id: str
    :param object_id: Required. Object id of the Principal
    :type object_id: str
    """

    _validation = {
        'tenant_id': {'required': True},
        'object_id': {'required': True},
    }

    _attribute_map = {
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'object_id': {'key': 'objectId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AdPrincipal, self).__init__(**kwargs)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.object_id = kwargs.get('object_id', None)
