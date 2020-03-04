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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import ComputeManagementClientConfiguration
from .operations import DisksOperations
from .operations import SnapshotsOperations
from .operations import DiskEncryptionSetsOperations
from . import models


class ComputeManagementClient(SDKClient):
    """Compute Client

    :ivar config: Configuration for client.
    :vartype config: ComputeManagementClientConfiguration

    :ivar disks: Disks operations
    :vartype disks: azure.mgmt.compute.v2019_11_01.operations.DisksOperations
    :ivar snapshots: Snapshots operations
    :vartype snapshots: azure.mgmt.compute.v2019_11_01.operations.SnapshotsOperations
    :ivar disk_encryption_sets: DiskEncryptionSets operations
    :vartype disk_encryption_sets: azure.mgmt.compute.v2019_11_01.operations.DiskEncryptionSetsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ComputeManagementClientConfiguration(credentials, subscription_id, base_url)
        super(ComputeManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-11-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.disks = DisksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.snapshots = SnapshotsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.disk_encryption_sets = DiskEncryptionSetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
