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


class EnvironmentOperationsPayload(Model):
    """Represents payload for any Environment operations like get, start, stop,
    connect.

    All required parameters must be populated in order to send to Azure.

    :param environment_id: Required. The resourceId of the environment
    :type environment_id: str
    """

    _validation = {
        'environment_id': {'required': True},
    }

    _attribute_map = {
        'environment_id': {'key': 'environmentId', 'type': 'str'},
    }

    def __init__(self, *, environment_id: str, **kwargs) -> None:
        super(EnvironmentOperationsPayload, self).__init__(**kwargs)
        self.environment_id = environment_id
