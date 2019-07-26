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

from .tracked_resource import TrackedResource


class SignalRResource(TrackedResource):
    """A class represent a SignalR service resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the service - e.g.
     "Microsoft.SignalRService/SignalR"
    :vartype type: str
    :param location: The GEO location of the SignalR service. e.g. West US |
     East US | North Central US | South Central US.
    :type location: str
    :param tags: Tags of the service which is a list of key value pairs that
     describe the resource.
    :type tags: dict[str, str]
    :param sku: SKU of the service.
    :type sku: ~azure.mgmt.signalr.models.ResourceSku
    :param host_name_prefix: Prefix for the hostName of the SignalR service.
     Retained for future use.
     The hostname will be of format:
     &lt;hostNamePrefix&gt;.service.signalr.net.
    :type host_name_prefix: str
    :param features: List of SignalR featureFlags. e.g. ServiceMode.
     FeatureFlags that are not included in the parameters for the update
     operation will not be modified.
     And the response will only include featureFlags that are explicitly set.
     When a featureFlag is not explicitly set, SignalR service will use its
     globally default value.
     But keep in mind, the default value doesn't mean "false". It varies in
     terms of different FeatureFlags.
    :type features: list[~azure.mgmt.signalr.models.SignalRFeature]
    :param cors: Cross-Origin Resource Sharing (CORS) settings.
    :type cors: ~azure.mgmt.signalr.models.SignalRCorsSettings
    :ivar provisioning_state: Provisioning state of the resource. Possible
     values include: 'Unknown', 'Succeeded', 'Failed', 'Canceled', 'Running',
     'Creating', 'Updating', 'Deleting', 'Moving'
    :vartype provisioning_state: str or
     ~azure.mgmt.signalr.models.ProvisioningState
    :ivar external_ip: The publicly accessible IP of the SignalR service.
    :vartype external_ip: str
    :ivar host_name: FQDN of the SignalR service instance. Format:
     xxx.service.signalr.net
    :vartype host_name: str
    :ivar public_port: The publicly accessible port of the SignalR service
     which is designed for browser/client side usage.
    :vartype public_port: int
    :ivar server_port: The publicly accessible port of the SignalR service
     which is designed for customer server side usage.
    :vartype server_port: int
    :param version: Version of the SignalR resource. Probably you need the
     same or higher version of client SDKs.
    :type version: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'external_ip': {'readonly': True},
        'host_name': {'readonly': True},
        'public_port': {'readonly': True},
        'server_port': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'ResourceSku'},
        'host_name_prefix': {'key': 'properties.hostNamePrefix', 'type': 'str'},
        'features': {'key': 'properties.features', 'type': '[SignalRFeature]'},
        'cors': {'key': 'properties.cors', 'type': 'SignalRCorsSettings'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'external_ip': {'key': 'properties.externalIP', 'type': 'str'},
        'host_name': {'key': 'properties.hostName', 'type': 'str'},
        'public_port': {'key': 'properties.publicPort', 'type': 'int'},
        'server_port': {'key': 'properties.serverPort', 'type': 'int'},
        'version': {'key': 'properties.version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SignalRResource, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.host_name_prefix = kwargs.get('host_name_prefix', None)
        self.features = kwargs.get('features', None)
        self.cors = kwargs.get('cors', None)
        self.provisioning_state = None
        self.external_ip = None
        self.host_name = None
        self.public_port = None
        self.server_port = None
        self.version = kwargs.get('version', None)
