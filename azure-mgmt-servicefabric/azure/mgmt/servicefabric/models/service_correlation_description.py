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


class ServiceCorrelationDescription(Model):
    """Creates a particular correlation between services.

    :param scheme: Possible values include: 'Invalid', 'Affinity',
     'AlignedAffinity', 'NonAlignedAffinity'
    :type scheme: str or :class:`enum <azure.mgmt.servicefabric.models.enum>`
    :param service_name:
    :type service_name: str
    """

    _validation = {
        'scheme': {'required': True},
        'service_name': {'required': True},
    }

    _attribute_map = {
        'scheme': {'key': 'Scheme', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
    }

    def __init__(self, scheme, service_name):
        self.scheme = scheme
        self.service_name = service_name
