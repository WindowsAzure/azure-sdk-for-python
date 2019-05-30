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

    All required parameters must be populated in order to send to Azure.

    :param scheme: Required. The ServiceCorrelationScheme which describes the
     relationship between this service and the service specified via
     ServiceName. Possible values include: 'Invalid', 'Affinity',
     'AlignedAffinity', 'NonAlignedAffinity'
    :type scheme: str or
     ~azure.mgmt.servicefabric.models.ServiceCorrelationScheme
    :param service_name: Required. The name of the service that the
     correlation relationship is established with.
    :type service_name: str
    """

    _validation = {
        'scheme': {'required': True},
        'service_name': {'required': True},
    }

    _attribute_map = {
        'scheme': {'key': 'scheme', 'type': 'str'},
        'service_name': {'key': 'serviceName', 'type': 'str'},
    }

    def __init__(self, *, scheme, service_name: str, **kwargs) -> None:
        super(ServiceCorrelationDescription, self).__init__(**kwargs)
        self.scheme = scheme
        self.service_name = service_name
