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


class Controller(TrackedResource):
    """Controller.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param tags: Tags for the Azure resource.
    :type tags: dict[str, str]
    :param location: Region where the Azure resource is located.
    :type location: str
    :ivar provisioning_state: Provisioning state of the Azure Dev Spaces
     Controller. Possible values include: 'Succeeded', 'Failed', 'Canceled',
     'Updating', 'Creating', 'Deleting'
    :vartype provisioning_state: str or
     ~azure.mgmt.devspaces.models.ProvisioningState
    :param host_suffix: Required. DNS suffix for public endpoints running in
     the Azure Dev Spaces Controller.
    :type host_suffix: str
    :ivar data_plane_fqdn: DNS name for accessing DataPlane services
    :vartype data_plane_fqdn: str
    :param target_container_host_resource_id: Required. Resource ID of the
     target container host
    :type target_container_host_resource_id: str
    :param target_container_host_credentials_base64: Required. Credentials of
     the target container host (base64).
    :type target_container_host_credentials_base64: str
    :param sku: Required.
    :type sku: ~azure.mgmt.devspaces.models.Sku
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'host_suffix': {'required': True},
        'data_plane_fqdn': {'readonly': True},
        'target_container_host_resource_id': {'required': True},
        'target_container_host_credentials_base64': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'host_suffix': {'key': 'properties.hostSuffix', 'type': 'str'},
        'data_plane_fqdn': {'key': 'properties.dataPlaneFqdn', 'type': 'str'},
        'target_container_host_resource_id': {'key': 'properties.targetContainerHostResourceId', 'type': 'str'},
        'target_container_host_credentials_base64': {'key': 'properties.targetContainerHostCredentialsBase64', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(self, **kwargs):
        super(Controller, self).__init__(**kwargs)
        self.provisioning_state = None
        self.host_suffix = kwargs.get('host_suffix', None)
        self.data_plane_fqdn = None
        self.target_container_host_resource_id = kwargs.get('target_container_host_resource_id', None)
        self.target_container_host_credentials_base64 = kwargs.get('target_container_host_credentials_base64', None)
        self.sku = kwargs.get('sku', None)
