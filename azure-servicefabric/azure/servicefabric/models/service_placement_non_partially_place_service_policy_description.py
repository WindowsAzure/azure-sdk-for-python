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

from .service_placement_policy_description import ServicePlacementPolicyDescription


class ServicePlacementNonPartiallyPlaceServicePolicyDescription(ServicePlacementPolicyDescription):
    """Describes the policy to be used for placement of a Service Fabric service
    where all replicas must be able to be placed in order for any replicas to
    be created.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'Type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServicePlacementNonPartiallyPlaceServicePolicyDescription, self).__init__(**kwargs)
        self.type = 'NonPartiallyPlaceService'
