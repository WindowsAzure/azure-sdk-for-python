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


class AccessInformationContract(Model):
    """Tenant access information contract of the API Management service.

    :param id: Identifier.
    :type id: str
    :param primary_key: Primary access key.
    :type primary_key: str
    :param secondary_key: Secondary access key.
    :type secondary_key: str
    :param enabled: Tenant access information of the API Management service.
    :type enabled: bool
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(AccessInformationContract, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.primary_key = kwargs.get('primary_key', None)
        self.secondary_key = kwargs.get('secondary_key', None)
        self.enabled = kwargs.get('enabled', None)
