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


class LogicAppReceiver(Model):
    """A logic app receiver.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the logic app receiver. Names must be
     unique across all receivers within an action group.
    :type name: str
    :param resource_id: Required. The azure resource id of the logic app
     receiver.
    :type resource_id: str
    :param callback_url: Required. The callback url where http request sent
     to.
    :type callback_url: str
    """

    _validation = {
        'name': {'required': True},
        'resource_id': {'required': True},
        'callback_url': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'callback_url': {'key': 'callbackUrl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(LogicAppReceiver, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.resource_id = kwargs.get('resource_id', None)
        self.callback_url = kwargs.get('callback_url', None)
