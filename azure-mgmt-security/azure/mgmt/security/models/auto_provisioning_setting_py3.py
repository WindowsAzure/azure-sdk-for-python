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

from .resource_py3 import Resource


class AutoProvisioningSetting(Resource):
    """Auto provisioning setting.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param auto_provision: Required. Describes what kind of security agent
     provisioning action to take. Possible values include: 'On', 'Off'
    :type auto_provision: str or ~azure.mgmt.security.models.AutoProvision
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'auto_provision': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'auto_provision': {'key': 'properties.autoProvision', 'type': 'str'},
    }

    def __init__(self, *, auto_provision, **kwargs) -> None:
        super(AutoProvisioningSetting, self).__init__(**kwargs)
        self.auto_provision = auto_provision
