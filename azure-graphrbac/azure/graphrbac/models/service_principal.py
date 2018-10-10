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

from .directory_object import DirectoryObject


class ServicePrincipal(DirectoryObject):
    """Active Directory service principal information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar object_id: The object ID.
    :vartype object_id: str
    :ivar deletion_timestamp: The time at which the directory object was
     deleted.
    :vartype deletion_timestamp: datetime
    :param object_type: Required. Constant filled by server.
    :type object_type: str
    :param display_name: The display name of the service principal.
    :type display_name: str
    :param app_id: The application ID.
    :type app_id: str
    :param service_principal_names: A collection of service principal names.
    :type service_principal_names: list[str]
    """

    _validation = {
        'object_id': {'readonly': True},
        'deletion_timestamp': {'readonly': True},
        'object_type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'object_id': {'key': 'objectId', 'type': 'str'},
        'deletion_timestamp': {'key': 'deletionTimestamp', 'type': 'iso-8601'},
        'object_type': {'key': 'objectType', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'app_id': {'key': 'appId', 'type': 'str'},
        'service_principal_names': {'key': 'servicePrincipalNames', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ServicePrincipal, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.app_id = kwargs.get('app_id', None)
        self.service_principal_names = kwargs.get('service_principal_names', None)
        self.object_type = 'ServicePrincipal'
