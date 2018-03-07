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

from msrest.service_client import ServiceClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling
import uuid
from .operations.application_gateways_operations import ApplicationGatewaysOperations
from .operations.express_route_circuit_authorizations_operations import ExpressRouteCircuitAuthorizationsOperations
from .operations.express_route_circuit_peerings_operations import ExpressRouteCircuitPeeringsOperations
from .operations.express_route_circuits_operations import ExpressRouteCircuitsOperations
from .operations.express_route_service_providers_operations import ExpressRouteServiceProvidersOperations
from .operations.load_balancers_operations import LoadBalancersOperations
from .operations.network_interfaces_operations import NetworkInterfacesOperations
from .operations.network_security_groups_operations import NetworkSecurityGroupsOperations
from .operations.security_rules_operations import SecurityRulesOperations
from .operations.public_ip_addresses_operations import PublicIPAddressesOperations
from .operations.route_tables_operations import RouteTablesOperations
from .operations.routes_operations import RoutesOperations
from .operations.usages_operations import UsagesOperations
from .operations.virtual_networks_operations import VirtualNetworksOperations
from .operations.subnets_operations import SubnetsOperations
from .operations.virtual_network_gateways_operations import VirtualNetworkGatewaysOperations
from .operations.virtual_network_gateway_connections_operations import VirtualNetworkGatewayConnectionsOperations
from .operations.local_network_gateways_operations import LocalNetworkGatewaysOperations
from . import models


class NetworkManagementClientConfiguration(AzureConfiguration):
    """Configuration for NetworkManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription credentials which uniquely
     identify the Microsoft Azure subscription. The subscription ID forms part
     of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(NetworkManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-network/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class NetworkManagementClient(object):
    """Network Client

    :ivar config: Configuration for client.
    :vartype config: NetworkManagementClientConfiguration

    :ivar application_gateways: ApplicationGateways operations
    :vartype application_gateways: azure.mgmt.network.v2015_06_15.operations.ApplicationGatewaysOperations
    :ivar express_route_circuit_authorizations: ExpressRouteCircuitAuthorizations operations
    :vartype express_route_circuit_authorizations: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitAuthorizationsOperations
    :ivar express_route_circuit_peerings: ExpressRouteCircuitPeerings operations
    :vartype express_route_circuit_peerings: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitPeeringsOperations
    :ivar express_route_circuits: ExpressRouteCircuits operations
    :vartype express_route_circuits: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitsOperations
    :ivar express_route_service_providers: ExpressRouteServiceProviders operations
    :vartype express_route_service_providers: azure.mgmt.network.v2015_06_15.operations.ExpressRouteServiceProvidersOperations
    :ivar load_balancers: LoadBalancers operations
    :vartype load_balancers: azure.mgmt.network.v2015_06_15.operations.LoadBalancersOperations
    :ivar network_interfaces: NetworkInterfaces operations
    :vartype network_interfaces: azure.mgmt.network.v2015_06_15.operations.NetworkInterfacesOperations
    :ivar network_security_groups: NetworkSecurityGroups operations
    :vartype network_security_groups: azure.mgmt.network.v2015_06_15.operations.NetworkSecurityGroupsOperations
    :ivar security_rules: SecurityRules operations
    :vartype security_rules: azure.mgmt.network.v2015_06_15.operations.SecurityRulesOperations
    :ivar public_ip_addresses: PublicIPAddresses operations
    :vartype public_ip_addresses: azure.mgmt.network.v2015_06_15.operations.PublicIPAddressesOperations
    :ivar route_tables: RouteTables operations
    :vartype route_tables: azure.mgmt.network.v2015_06_15.operations.RouteTablesOperations
    :ivar routes: Routes operations
    :vartype routes: azure.mgmt.network.v2015_06_15.operations.RoutesOperations
    :ivar usages: Usages operations
    :vartype usages: azure.mgmt.network.v2015_06_15.operations.UsagesOperations
    :ivar virtual_networks: VirtualNetworks operations
    :vartype virtual_networks: azure.mgmt.network.v2015_06_15.operations.VirtualNetworksOperations
    :ivar subnets: Subnets operations
    :vartype subnets: azure.mgmt.network.v2015_06_15.operations.SubnetsOperations
    :ivar virtual_network_gateways: VirtualNetworkGateways operations
    :vartype virtual_network_gateways: azure.mgmt.network.v2015_06_15.operations.VirtualNetworkGatewaysOperations
    :ivar virtual_network_gateway_connections: VirtualNetworkGatewayConnections operations
    :vartype virtual_network_gateway_connections: azure.mgmt.network.v2015_06_15.operations.VirtualNetworkGatewayConnectionsOperations
    :ivar local_network_gateways: LocalNetworkGateways operations
    :vartype local_network_gateways: azure.mgmt.network.v2015_06_15.operations.LocalNetworkGatewaysOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription credentials which uniquely
     identify the Microsoft Azure subscription. The subscription ID forms part
     of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = NetworkManagementClientConfiguration(credentials, subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2015-06-15'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application_gateways = ApplicationGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuit_authorizations = ExpressRouteCircuitAuthorizationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuit_peerings = ExpressRouteCircuitPeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuits = ExpressRouteCircuitsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_service_providers = ExpressRouteServiceProvidersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancers = LoadBalancersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_interfaces = NetworkInterfacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_security_groups = NetworkSecurityGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_rules = SecurityRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.public_ip_addresses = PublicIPAddressesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.route_tables = RouteTablesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.routes = RoutesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subnets = SubnetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateways = VirtualNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateway_connections = VirtualNetworkGatewayConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.local_network_gateways = LocalNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)

    def check_dns_name_availability(
            self, location, domain_name_label=None, custom_headers=None, raw=False, **operation_config):
        """Checks whether a domain name in the cloudapp.net zone is available for
        use.

        :param location: The location of the domain name.
        :type location: str
        :param domain_name_label: The domain name to be verified. It must
         conform to the following regular expression:
         ^[a-z][a-z0-9-]{1,61}[a-z0-9]$.
        :type domain_name_label: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: DnsNameAvailabilityResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.network.v2015_06_15.models.DnsNameAvailabilityResult or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.check_dns_name_availability.metadata['url']
        path_format_arguments = {
            'location': self._serialize.url("location", location, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if domain_name_label is not None:
            query_parameters['domainNameLabel'] = self._serialize.query("domain_name_label", domain_name_label, 'str')
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('DnsNameAvailabilityResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_dns_name_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{location}/CheckDnsNameAvailability'}
