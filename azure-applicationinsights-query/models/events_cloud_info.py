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


class EventsCloudInfo(Model):
    """Cloud info for an event result.

    :param role_name: Role name of the cloud
    :type role_name: str
    :param role_instance: Role instance of the cloud
    :type role_instance: str
    """

    _attribute_map = {
        'role_name': {'key': 'roleName', 'type': 'str'},
        'role_instance': {'key': 'roleInstance', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EventsCloudInfo, self).__init__(**kwargs)
        self.role_name = kwargs.get('role_name', None)
        self.role_instance = kwargs.get('role_instance', None)
