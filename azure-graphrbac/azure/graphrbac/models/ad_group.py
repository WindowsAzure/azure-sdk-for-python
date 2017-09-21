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


class ADGroup(Model):
    """Active Directory group information.

    :param object_id: The object ID.
    :type object_id: str
    :param object_type: The object type.
    :type object_type: str
    :param display_name: The display name of the group.
    :type display_name: str
    :param security_enabled: Whether the group is security-enable.
    :type security_enabled: bool
    :param mail: The primary email address of the group.
    :type mail: str
    """

    _attribute_map = {
        'object_id': {'key': 'objectId', 'type': 'str'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'security_enabled': {'key': 'securityEnabled', 'type': 'bool'},
        'mail': {'key': 'mail', 'type': 'str'},
    }

    def __init__(self, object_id=None, object_type=None, display_name=None, security_enabled=None, mail=None):
        self.object_id = object_id
        self.object_type = object_type
        self.display_name = display_name
        self.security_enabled = security_enabled
        self.mail = mail
