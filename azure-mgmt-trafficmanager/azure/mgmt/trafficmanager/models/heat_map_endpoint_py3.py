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


class HeatMapEndpoint(Model):
    """Class which is a sparse representation of a Traffic Manager endpoint.

    :param resource_id: The ARM Resource ID of this Traffic Manager endpoint.
    :type resource_id: str
    :param endpoint_id: A number uniquely identifying this endpoint in query
     experiences.
    :type endpoint_id: int
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'endpoint_id': {'key': 'endpointId', 'type': 'int'},
    }

    def __init__(self, *, resource_id: str=None, endpoint_id: int=None, **kwargs) -> None:
        super(HeatMapEndpoint, self).__init__(**kwargs)
        self.resource_id = resource_id
        self.endpoint_id = endpoint_id
