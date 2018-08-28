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

from .resource import Resource


class ContainerService(Resource):
    """Container service.

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
    :param orchestrator_profile: Required. Profile for the container service
     orchestrator.
    :type orchestrator_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceOrchestratorProfile
    :param custom_profile: Properties to configure a custom container service
     cluster.
    :type custom_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceCustomProfile
    :param service_principal_profile: Information about a service principal
     identity for the cluster to use for manipulating Azure APIs. Exact one of
     secret or keyVaultSecretRef need to be specified.
    :type service_principal_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceServicePrincipalProfile
    :param master_profile: Required. Profile for the container service master.
    :type master_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceMasterProfile
    :param agent_pool_profiles: Properties of the agent pool.
    :type agent_pool_profiles:
     list[~azure.mgmt.containerservice.models.ContainerServiceAgentPoolProfile]
    :param windows_profile: Profile for Windows VMs in the container service
     cluster.
    :type windows_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceWindowsProfile
    :param linux_profile: Required. Profile for Linux VMs in the container
     service cluster.
    :type linux_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceLinuxProfile
    :param diagnostics_profile: Profile for diagnostics in the container
     service cluster.
    :type diagnostics_profile:
     ~azure.mgmt.containerservice.models.ContainerServiceDiagnosticsProfile
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'orchestrator_profile': {'required': True},
        'master_profile': {'required': True},
        'linux_profile': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'orchestrator_profile': {'key': 'properties.orchestratorProfile', 'type': 'ContainerServiceOrchestratorProfile'},
        'custom_profile': {'key': 'properties.customProfile', 'type': 'ContainerServiceCustomProfile'},
        'service_principal_profile': {'key': 'properties.servicePrincipalProfile', 'type': 'ContainerServiceServicePrincipalProfile'},
        'master_profile': {'key': 'properties.masterProfile', 'type': 'ContainerServiceMasterProfile'},
        'agent_pool_profiles': {'key': 'properties.agentPoolProfiles', 'type': '[ContainerServiceAgentPoolProfile]'},
        'windows_profile': {'key': 'properties.windowsProfile', 'type': 'ContainerServiceWindowsProfile'},
        'linux_profile': {'key': 'properties.linuxProfile', 'type': 'ContainerServiceLinuxProfile'},
        'diagnostics_profile': {'key': 'properties.diagnosticsProfile', 'type': 'ContainerServiceDiagnosticsProfile'},
    }

    def __init__(self, **kwargs):
        super(ContainerService, self).__init__(**kwargs)
        self.provisioning_state = None
        self.orchestrator_profile = kwargs.get('orchestrator_profile', None)
        self.custom_profile = kwargs.get('custom_profile', None)
        self.service_principal_profile = kwargs.get('service_principal_profile', None)
        self.master_profile = kwargs.get('master_profile', None)
        self.agent_pool_profiles = kwargs.get('agent_pool_profiles', None)
        self.windows_profile = kwargs.get('windows_profile', None)
        self.linux_profile = kwargs.get('linux_profile', None)
        self.diagnostics_profile = kwargs.get('diagnostics_profile', None)
