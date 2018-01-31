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
    :param containers: The containers within the container group.
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
    :param os_type: The operating system type required by the containers in
     the container group. Possible values include: 'Windows', 'Linux'
    :type os_type: str or
     ~azure.mgmt.containerinstance.models.OperatingSystemTypes
    :param volumes: The list of volumes that can be mounted by containers in
     this container group.
    :type volumes: list[~azure.mgmt.containerinstance.models.Volume]
    :ivar instance_view: The instance view of the container group. Only valid
     in response.
    :vartype instance_view:
     ~azure.mgmt.containerinstance.models.ContainerGroupPropertiesInstanceView
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
    }

    def __init__(self, containers, os_type, location=None, tags=None, image_registry_credentials=None, restart_policy=None, ip_address=None, volumes=None):
        super(ContainerGroup, self).__init__(location=location, tags=tags)
        self.provisioning_state = None
        self.containers = containers
        self.image_registry_credentials = image_registry_credentials
        self.restart_policy = restart_policy
        self.ip_address = ip_address
        self.os_type = os_type
        self.volumes = volumes
        self.instance_view = None
