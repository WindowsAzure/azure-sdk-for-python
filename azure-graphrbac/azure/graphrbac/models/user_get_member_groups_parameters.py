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


class UserGetMemberGroupsParameters(Model):
    """Request parameters for GetMemberGroups API call.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param security_enabled_only: Required. If true, only membership in
     security-enabled groups should be checked. Otherwise, membership in all
     groups should be checked.
    :type security_enabled_only: bool
    """

    _validation = {
        'security_enabled_only': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'security_enabled_only': {'key': 'securityEnabledOnly', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(UserGetMemberGroupsParameters, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.security_enabled_only = kwargs.get('security_enabled_only', None)
