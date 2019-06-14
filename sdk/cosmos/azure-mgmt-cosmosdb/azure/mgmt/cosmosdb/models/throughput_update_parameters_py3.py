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


class ThroughputUpdateParameters(Model):
    """Parameters to update Cosmos DB resource throughput.

    All required parameters must be populated in order to send to Azure.

    :param resource: Required. The standard JSON format of a resource
     throughput
    :type resource: ~azure.mgmt.cosmosdb.models.ThroughputResource
    """

    _validation = {
        'resource': {'required': True},
    }

    _attribute_map = {
        'resource': {'key': 'properties.resource', 'type': 'ThroughputResource'},
    }

    def __init__(self, *, resource, **kwargs) -> None:
        super(ThroughputUpdateParameters, self).__init__(**kwargs)
        self.resource = resource
