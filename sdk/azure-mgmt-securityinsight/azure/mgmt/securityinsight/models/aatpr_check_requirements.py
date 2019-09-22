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


class AATPRCheckRequirements(Model):
    """AATP (Azure Advanced Threat Protection) requirements check properties.

    :param tenant_id: The tenant id to connect to, and get the data from.
    :type tenant_id: str
    """

    _attribute_map = {
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AATPRCheckRequirements, self).__init__(**kwargs)
        self.tenant_id = kwargs.get('tenant_id', None)
