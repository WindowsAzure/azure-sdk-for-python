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


class CopyRequestTargetInformation(Model):
    """Information about target subscription.

    :param endpoint: Get or set endpoint path.
    :type endpoint: str
    :param resource_id: Get or set resource identifier.
    :type resource_id: str
    """

    _validation = {
        'endpoint': {'max_length': 2048, 'min_length': 0},
        'resource_id': {'max_length': 2048, 'min_length': 0},
    }

    _attribute_map = {
        'endpoint': {'key': 'endpoint', 'type': 'str'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
    }

    def __init__(self, *, endpoint: str=None, resource_id: str=None, **kwargs) -> None:
        super(CopyRequestTargetInformation, self).__init__(**kwargs)
        self.endpoint = endpoint
        self.resource_id = resource_id
