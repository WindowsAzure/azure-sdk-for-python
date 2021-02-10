# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import NetAppManagementClientConfiguration
from .operations import Operations
from .operations import NetAppResourceOperations
from .operations import AccountsOperations
from .operations import PoolsOperations
from .operations import VolumesOperations
from .operations import SnapshotsOperations
from .operations import SnapshotPoliciesOperations
from .operations import AccountBackupsOperations
from .operations import BackupsOperations
from .operations import BackupPoliciesOperations
from .operations import VaultsOperations
from .. import models


class NetAppManagementClient(object):
    """Microsoft NetApp Azure Resource Provider specification.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.netapp.aio.operations.Operations
    :ivar net_app_resource: NetAppResourceOperations operations
    :vartype net_app_resource: azure.mgmt.netapp.aio.operations.NetAppResourceOperations
    :ivar accounts: AccountsOperations operations
    :vartype accounts: azure.mgmt.netapp.aio.operations.AccountsOperations
    :ivar pools: PoolsOperations operations
    :vartype pools: azure.mgmt.netapp.aio.operations.PoolsOperations
    :ivar volumes: VolumesOperations operations
    :vartype volumes: azure.mgmt.netapp.aio.operations.VolumesOperations
    :ivar snapshots: SnapshotsOperations operations
    :vartype snapshots: azure.mgmt.netapp.aio.operations.SnapshotsOperations
    :ivar snapshot_policies: SnapshotPoliciesOperations operations
    :vartype snapshot_policies: azure.mgmt.netapp.aio.operations.SnapshotPoliciesOperations
    :ivar account_backups: AccountBackupsOperations operations
    :vartype account_backups: azure.mgmt.netapp.aio.operations.AccountBackupsOperations
    :ivar backups: BackupsOperations operations
    :vartype backups: azure.mgmt.netapp.aio.operations.BackupsOperations
    :ivar backup_policies: BackupPoliciesOperations operations
    :vartype backup_policies: azure.mgmt.netapp.aio.operations.BackupPoliciesOperations
    :ivar vaults: VaultsOperations operations
    :vartype vaults: azure.mgmt.netapp.aio.operations.VaultsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials which uniquely identify Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = NetAppManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.net_app_resource = NetAppResourceOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.accounts = AccountsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.pools = PoolsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.volumes = VolumesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.snapshots = SnapshotsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.snapshot_policies = SnapshotPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.account_backups = AccountBackupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.backups = BackupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.backup_policies = BackupPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vaults = VaultsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "NetAppManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
