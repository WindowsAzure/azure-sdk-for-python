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


class ContainerGroup(Resource):
    """A container group.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource id.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :ivar provisioning_state: The provisioning state of the container group.
     This only appears in the response.
    :vartype provisioning_state: str
    :param containers: Required. The containers within the container group.
    :type containers: list[~azure.mgmt.containerinstance.models.Container]
    :param image_registry_credentials: The image registry credentials by which
     the container group is created from.
    :type image_registry_credentials:
     list[~azure.mgmt.containerinstance.models.ImageRegistryCredential]
    :param restart_policy: Restart policy for all containers within the
     container group.
     - `Always` Always restart
     - `OnFailure` Restart on failure
     - `Never` Never restart
     . Possible values include: 'Always', 'OnFailure', 'Never'
    :type restart_policy: str or
     ~azure.mgmt.containerinstance.models.ContainerGroupRestartPolicy
    :param ip_address: The IP address type of the container group.
    :type ip_address: ~azure.mgmt.containerinstance.models.IpAddress
    :param os_type: Required. The operating system type required by the
     containers in the container group. Possible values include: 'Windows',
     'Linux'
    :type os_type: str or
     ~azure.mgmt.containerinstance.models.OperatingSystemTypes
    :param volumes: The list of volumes that can be mounted by containers in
     this container group.
    :type volumes: list[~azure.mgmt.containerinstance.models.Volume]
    :ivar instance_view: The instance view of the container group. Only valid
     in response.
    :vartype instance_view:
     ~azure.mgmt.containerinstance.models.ContainerGroupPropertiesInstanceView
    :param diagnostics: The diagnostic information for a container group.
    :type diagnostics:
     ~azure.mgmt.containerinstance.models.ContainerGroupDiagnostics
    :param network_profile: The network profile information for a container
     group.
    :type network_profile:
     ~azure.mgmt.containerinstance.models.ContainerGroupNetworkProfile
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'containers': {'required': True},
        'os_type': {'required': True},
        'instance_view': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'containers': {'key': 'properties.containers', 'type': '[Container]'},
        'image_registry_credentials': {'key': 'properties.imageRegistryCredentials', 'type': '[ImageRegistryCredential]'},
        'restart_policy': {'key': 'properties.restartPolicy', 'type': 'str'},
        'ip_address': {'key': 'properties.ipAddress', 'type': 'IpAddress'},
        'os_type': {'key': 'properties.osType', 'type': 'str'},
        'volumes': {'key': 'properties.volumes', 'type': '[Volume]'},
        'instance_view': {'key': 'properties.instanceView', 'type': 'ContainerGroupPropertiesInstanceView'},
        'diagnostics': {'key': 'properties.diagnostics', 'type': 'ContainerGroupDiagnostics'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'ContainerGroupNetworkProfile'},
    }

    def __init__(self, **kwargs):
        super(ContainerGroup, self).__init__(**kwargs)
        self.provisioning_state = None
        self.containers = kwargs.get('containers', None)
        self.image_registry_credentials = kwargs.get('image_registry_credentials', None)
        self.restart_policy = kwargs.get('restart_policy', None)
        self.ip_address = kwargs.get('ip_address', None)
        self.os_type = kwargs.get('os_type', None)
        self.volumes = kwargs.get('volumes', None)
        self.instance_view = None
        self.diagnostics = kwargs.get('diagnostics', None)
        self.network_profile = kwargs.get('network_profile', None)
