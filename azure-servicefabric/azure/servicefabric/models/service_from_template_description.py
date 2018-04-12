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


class ServiceFromTemplateDescription(Model):
    """Defines description for creating a Service Fabric service from a template
    defined in the application manifest.
    .

    All required parameters must be populated in order to send to Azure.

    :param application_name: Required. The name of the application, including
     the 'fabric:' URI scheme.
    :type application_name: str
    :param service_name: Required. The full name of the service with 'fabric:'
     URI scheme.
    :type service_name: str
    :param service_type_name: Required. Name of the service type as specified
     in the service manifest.
    :type service_type_name: str
    :param initialization_data: The initialization data for the newly created
     service instance.
    :type initialization_data: list[int]
    :param service_package_activation_mode: The activation mode of service
     package to be used for a service. Possible values include:
     'SharedProcess', 'ExclusiveProcess'
    :type service_package_activation_mode: str or
     ~azure.servicefabric.models.ServicePackageActivationMode
    :param service_dns_name: The DNS name of the service. It requires the DNS
     system service to be enabled in Service Fabric cluster.
    :type service_dns_name: str
    """

    _validation = {
        'application_name': {'required': True},
        'service_name': {'required': True},
        'service_type_name': {'required': True},
    }

    _attribute_map = {
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
        'initialization_data': {'key': 'InitializationData', 'type': '[int]'},
        'service_package_activation_mode': {'key': 'ServicePackageActivationMode', 'type': 'str'},
        'service_dns_name': {'key': 'ServiceDnsName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServiceFromTemplateDescription, self).__init__(**kwargs)
        self.application_name = kwargs.get('application_name', None)
        self.service_name = kwargs.get('service_name', None)
        self.service_type_name = kwargs.get('service_type_name', None)
        self.initialization_data = kwargs.get('initialization_data', None)
        self.service_package_activation_mode = kwargs.get('service_package_activation_mode', None)
        self.service_dns_name = kwargs.get('service_dns_name', None)
