# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class ApplicationGateway(Resource):
    """
    ApplicationGateways resource

    :param id: Resource Id
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param sku: Gets or sets sku of application gateway resource
    :type sku: :class:`ApplicationGatewaySku
     <azure.mgmt.network.models.ApplicationGatewaySku>`
    :param operational_state: Gets operational state of application gateway
     resource. Possible values include: 'Stopped', 'Starting', 'Running',
     'Stopping'
    :type operational_state: str
    :param gateway_ip_configurations: Gets or sets subnets of application
     gateway resource
    :type gateway_ip_configurations: list of
     :class:`ApplicationGatewayIPConfiguration
     <azure.mgmt.network.models.ApplicationGatewayIPConfiguration>`
    :param ssl_certificates: Gets or sets ssl certificates of application
     gateway resource
    :type ssl_certificates: list of :class:`ApplicationGatewaySslCertificate
     <azure.mgmt.network.models.ApplicationGatewaySslCertificate>`
    :param frontend_ip_configurations: Gets or sets frontend IP addresses of
     application gateway resource
    :type frontend_ip_configurations: list of
     :class:`ApplicationGatewayFrontendIPConfiguration
     <azure.mgmt.network.models.ApplicationGatewayFrontendIPConfiguration>`
    :param frontend_ports: Gets or sets frontend ports of application gateway
     resource
    :type frontend_ports: list of :class:`ApplicationGatewayFrontendPort
     <azure.mgmt.network.models.ApplicationGatewayFrontendPort>`
    :param probes: Gets or sets probes of application gateway resource
    :type probes: list of :class:`ApplicationGatewayProbe
     <azure.mgmt.network.models.ApplicationGatewayProbe>`
    :param backend_address_pools: Gets or sets backend address pool of
     application gateway resource
    :type backend_address_pools: list of
     :class:`ApplicationGatewayBackendAddressPool
     <azure.mgmt.network.models.ApplicationGatewayBackendAddressPool>`
    :param backend_http_settings_collection: Gets or sets backend http
     settings of application gateway resource
    :type backend_http_settings_collection: list of
     :class:`ApplicationGatewayBackendHttpSettings
     <azure.mgmt.network.models.ApplicationGatewayBackendHttpSettings>`
    :param http_listeners: Gets or sets HTTP listeners of application gateway
     resource
    :type http_listeners: list of :class:`ApplicationGatewayHttpListener
     <azure.mgmt.network.models.ApplicationGatewayHttpListener>`
    :param url_path_maps: Gets or sets URL path map of application gateway
     resource
    :type url_path_maps: list of :class:`ApplicationGatewayUrlPathMap
     <azure.mgmt.network.models.ApplicationGatewayUrlPathMap>`
    :param request_routing_rules: Gets or sets request routing rules of
     application gateway resource
    :type request_routing_rules: list of
     :class:`ApplicationGatewayRequestRoutingRule
     <azure.mgmt.network.models.ApplicationGatewayRequestRoutingRule>`
    :param resource_guid: Gets or sets resource guid property of the
     ApplicationGateway resource
    :type resource_guid: str
    :param provisioning_state: Gets or sets Provisioning state of the
     ApplicationGateway resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param etag: Gets a unique read-only string that changes whenever the
     resource is updated
    :type etag: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'properties.sku', 'type': 'ApplicationGatewaySku'},
        'operational_state': {'key': 'properties.operationalState', 'type': 'ApplicationGatewayOperationalState'},
        'gateway_ip_configurations': {'key': 'properties.gatewayIPConfigurations', 'type': '[ApplicationGatewayIPConfiguration]'},
        'ssl_certificates': {'key': 'properties.sslCertificates', 'type': '[ApplicationGatewaySslCertificate]'},
        'frontend_ip_configurations': {'key': 'properties.frontendIPConfigurations', 'type': '[ApplicationGatewayFrontendIPConfiguration]'},
        'frontend_ports': {'key': 'properties.frontendPorts', 'type': '[ApplicationGatewayFrontendPort]'},
        'probes': {'key': 'properties.probes', 'type': '[ApplicationGatewayProbe]'},
        'backend_address_pools': {'key': 'properties.backendAddressPools', 'type': '[ApplicationGatewayBackendAddressPool]'},
        'backend_http_settings_collection': {'key': 'properties.backendHttpSettingsCollection', 'type': '[ApplicationGatewayBackendHttpSettings]'},
        'http_listeners': {'key': 'properties.httpListeners', 'type': '[ApplicationGatewayHttpListener]'},
        'url_path_maps': {'key': 'properties.urlPathMaps', 'type': '[ApplicationGatewayUrlPathMap]'},
        'request_routing_rules': {'key': 'properties.requestRoutingRules', 'type': '[ApplicationGatewayRequestRoutingRule]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, type=None, location=None, tags=None, sku=None, operational_state=None, gateway_ip_configurations=None, ssl_certificates=None, frontend_ip_configurations=None, frontend_ports=None, probes=None, backend_address_pools=None, backend_http_settings_collection=None, http_listeners=None, url_path_maps=None, request_routing_rules=None, resource_guid=None, provisioning_state=None, etag=None, **kwargs):
        super(ApplicationGateway, self).__init__(id=id, name=name, type=type, location=location, tags=tags, **kwargs)
        self.sku = sku
        self.operational_state = operational_state
        self.gateway_ip_configurations = gateway_ip_configurations
        self.ssl_certificates = ssl_certificates
        self.frontend_ip_configurations = frontend_ip_configurations
        self.frontend_ports = frontend_ports
        self.probes = probes
        self.backend_address_pools = backend_address_pools
        self.backend_http_settings_collection = backend_http_settings_collection
        self.http_listeners = http_listeners
        self.url_path_maps = url_path_maps
        self.request_routing_rules = request_routing_rules
        self.resource_guid = resource_guid
        self.provisioning_state = provisioning_state
        self.etag = etag
