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


class DiscoveredSecuritySolution(Model):
    """DiscoveredSecuritySolution.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :ivar location: Location where the resource is stored
    :vartype location: str
    :param security_family: Required. The security family of the discovered
     solution. Possible values include: 'Waf', 'Ngfw', 'SaasWaf', 'Va'
    :type security_family: str or ~azure.mgmt.security.models.SecurityFamily
    :param offer: Required. The security solutions' image offer
    :type offer: str
    :param publisher: Required. The security solutions' image publisher
    :type publisher: str
    :param sku: Required. The security solutions' image sku
    :type sku: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'readonly': True},
        'security_family': {'required': True},
        'offer': {'required': True},
        'publisher': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'security_family': {'key': 'properties.securityFamily', 'type': 'str'},
        'offer': {'key': 'properties.offer', 'type': 'str'},
        'publisher': {'key': 'properties.publisher', 'type': 'str'},
        'sku': {'key': 'properties.sku', 'type': 'str'},
    }

    def __init__(self, *, security_family, offer: str, publisher: str, sku: str, **kwargs) -> None:
        super(DiscoveredSecuritySolution, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = None
        self.security_family = security_family
        self.offer = offer
        self.publisher = publisher
        self.sku = sku
