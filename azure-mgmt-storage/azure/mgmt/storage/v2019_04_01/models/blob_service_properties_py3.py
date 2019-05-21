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


class BlobServiceProperties(Resource):
    """The properties of a storage account’s Blob service.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param cors: Specifies CORS rules for the Blob service. You can include up
     to five CorsRule elements in the request. If no CorsRule elements are
     included in the request body, all CORS rules will be deleted, and CORS
     will be disabled for the Blob service.
    :type cors: ~azure.mgmt.storage.v2019_04_01.models.CorsRules
    :param default_service_version: DefaultServiceVersion indicates the
     default version to use for requests to the Blob service if an incoming
     request’s version is not specified. Possible values include version
     2008-10-27 and all more recent versions.
    :type default_service_version: str
    :param delete_retention_policy: The blob service properties for soft
     delete.
    :type delete_retention_policy:
     ~azure.mgmt.storage.v2019_04_01.models.DeleteRetentionPolicy
    :param automatic_snapshot_policy_enabled: Automatic Snapshot is enabled if
     set to true.
    :type automatic_snapshot_policy_enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'cors': {'key': 'properties.cors', 'type': 'CorsRules'},
        'default_service_version': {'key': 'properties.defaultServiceVersion', 'type': 'str'},
        'delete_retention_policy': {'key': 'properties.deleteRetentionPolicy', 'type': 'DeleteRetentionPolicy'},
        'automatic_snapshot_policy_enabled': {'key': 'properties.automaticSnapshotPolicyEnabled', 'type': 'bool'},
    }

    def __init__(self, *, cors=None, default_service_version: str=None, delete_retention_policy=None, automatic_snapshot_policy_enabled: bool=None, **kwargs) -> None:
        super(BlobServiceProperties, self).__init__(**kwargs)
        self.cors = cors
        self.default_service_version = default_service_version
        self.delete_retention_policy = delete_retention_policy
        self.automatic_snapshot_policy_enabled = automatic_snapshot_policy_enabled
