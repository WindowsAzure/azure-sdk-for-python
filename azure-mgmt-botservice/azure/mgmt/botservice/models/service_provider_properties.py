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


class ServiceProviderProperties(Model):
    """The Object used to describe a Service Provider supported by Bot Service.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Id for Service Provider
    :vartype id: str
    :ivar display_name: Diplay Name of the Service Provider
    :vartype display_name: str
    :ivar service_provider_name: Diplay Name of the Service Provider
    :vartype service_provider_name: str
    :ivar dev_portal_url: Diplay Name of the Service Provider
    :vartype dev_portal_url: str
    :ivar icon_url: Diplay Name of the Service Provider
    :vartype icon_url: str
    :param parameters: The list of parameters for the Service Provider
    :type parameters:
     list[~azure.mgmt.botservice.models.ServiceProviderParameter]
    """

    _validation = {
        'id': {'readonly': True},
        'display_name': {'readonly': True},
        'service_provider_name': {'readonly': True},
        'dev_portal_url': {'readonly': True},
        'icon_url': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'service_provider_name': {'key': 'serviceProviderName', 'type': 'str'},
        'dev_portal_url': {'key': 'devPortalUrl', 'type': 'str'},
        'icon_url': {'key': 'iconUrl', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '[ServiceProviderParameter]'},
    }

    def __init__(self, parameters=None):
        self.id = None
        self.display_name = None
        self.service_provider_name = None
        self.dev_portal_url = None
        self.icon_url = None
        self.parameters = parameters
