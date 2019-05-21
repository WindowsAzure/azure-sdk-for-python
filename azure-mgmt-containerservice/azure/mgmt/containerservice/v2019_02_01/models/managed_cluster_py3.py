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

from .resource_py3 import Resource


class ManagedCluster(Resource):
    """Managed cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :ivar provisioning_state: The current deployment or provisioning state,
     which only appears in the response.
    :vartype provisioning_state: str
    :param kubernetes_version: Version of Kubernetes specified when creating
     the managed cluster.
    :type kubernetes_version: str
    :param dns_prefix: DNS prefix specified when creating the managed cluster.
    :type dns_prefix: str
    :ivar fqdn: FQDN for the master pool.
    :vartype fqdn: str
    :param agent_pool_profiles: Properties of the agent pool.
    :type agent_pool_profiles:
     list[~azure.mgmt.containerservice.v2019_02_01.models.ManagedClusterAgentPoolProfile]
    :param linux_profile: Profile for Linux VMs in the container service
     cluster.
    :type linux_profile:
     ~azure.mgmt.containerservice.v2019_02_01.models.ContainerServiceLinuxProfile
    :param service_principal_profile: Information about a service principal
     identity for the cluster to use for manipulating Azure APIs.
    :type service_principal_profile:
     ~azure.mgmt.containerservice.v2019_02_01.models.ManagedClusterServicePrincipalProfile
    :param addon_profiles: Profile of managed cluster add-on.
    :type addon_profiles: dict[str,
     ~azure.mgmt.containerservice.v2019_02_01.models.ManagedClusterAddonProfile]
    :ivar node_resource_group: Name of the resource group containing agent
     pool nodes.
    :vartype node_resource_group: str
    :param enable_rbac: Whether to enable Kubernetes Role-Based Access
     Control.
    :type enable_rbac: bool
    :param enable_pod_security_policy: (PREVIEW) Whether to enable Kubernetes
     Pod security policy.
    :type enable_pod_security_policy: bool
    :param network_profile: Profile of network configuration.
    :type network_profile:
     ~azure.mgmt.containerservice.v2019_02_01.models.ContainerServiceNetworkProfile
    :param aad_profile: Profile of Azure Active Directory configuration.
    :type aad_profile:
     ~azure.mgmt.containerservice.v2019_02_01.models.ManagedClusterAADProfile
    :param api_server_authorized_ip_ranges: (PREVIEW) Authorized IP Ranges to
     kubernetes API server.
    :type api_server_authorized_ip_ranges: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'fqdn': {'readonly': True},
        'node_resource_group': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'kubernetes_version': {'key': 'properties.kubernetesVersion', 'type': 'str'},
        'dns_prefix': {'key': 'properties.dnsPrefix', 'type': 'str'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'agent_pool_profiles': {'key': 'properties.agentPoolProfiles', 'type': '[ManagedClusterAgentPoolProfile]'},
        'linux_profile': {'key': 'properties.linuxProfile', 'type': 'ContainerServiceLinuxProfile'},
        'service_principal_profile': {'key': 'properties.servicePrincipalProfile', 'type': 'ManagedClusterServicePrincipalProfile'},
        'addon_profiles': {'key': 'properties.addonProfiles', 'type': '{ManagedClusterAddonProfile}'},
        'node_resource_group': {'key': 'properties.nodeResourceGroup', 'type': 'str'},
        'enable_rbac': {'key': 'properties.enableRBAC', 'type': 'bool'},
        'enable_pod_security_policy': {'key': 'properties.enablePodSecurityPolicy', 'type': 'bool'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'ContainerServiceNetworkProfile'},
        'aad_profile': {'key': 'properties.aadProfile', 'type': 'ManagedClusterAADProfile'},
        'api_server_authorized_ip_ranges': {'key': 'properties.apiServerAuthorizedIPRanges', 'type': '[str]'},
    }

    def __init__(self, *, location: str, tags=None, kubernetes_version: str=None, dns_prefix: str=None, agent_pool_profiles=None, linux_profile=None, service_principal_profile=None, addon_profiles=None, enable_rbac: bool=None, enable_pod_security_policy: bool=None, network_profile=None, aad_profile=None, api_server_authorized_ip_ranges=None, **kwargs) -> None:
        super(ManagedCluster, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.kubernetes_version = kubernetes_version
        self.dns_prefix = dns_prefix
        self.fqdn = None
        self.agent_pool_profiles = agent_pool_profiles
        self.linux_profile = linux_profile
        self.service_principal_profile = service_principal_profile
        self.addon_profiles = addon_profiles
        self.node_resource_group = None
        self.enable_rbac = enable_rbac
        self.enable_pod_security_policy = enable_pod_security_policy
        self.network_profile = network_profile
        self.aad_profile = aad_profile
        self.api_server_authorized_ip_ranges = api_server_authorized_ip_ranges
