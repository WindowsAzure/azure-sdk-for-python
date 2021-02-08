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
from msrest import Serializer, Deserializer
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.core.polling.async_base_polling import AsyncLROBasePolling


class KeyVaultClientOperationsMixin(object):

    async def begin_full_backup(
        self,
        vault_base_url: str,
        azure_storage_blob_container_uri: Optional["models.SASTokenParameter"] = None,
        **kwargs
    ) -> AsyncLROPoller["models.FullBackupOperation"]:
        """Creates a full backup using a user-provided SAS token to an Azure blob storage container.

        :param vault_base_url: The vault name, for example https://myvault.vault.azure.net.
        :type vault_base_url: str
        :param azure_storage_blob_container_uri: Azure blob shared access signature token pointing to a
         valid Azure blob container where full backup needs to be stored. This token needs to be valid
         for at least next 24 hours from the time of making this call.
        :type azure_storage_blob_container_uri: ~azure.keyvault.v7_2.models.SASTokenParameter
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either FullBackupOperation or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.keyvault.v7_2.models.FullBackupOperation]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        api_version = self._get_api_version('begin_full_backup')
        if api_version == '7.2-preview':
            from ..v7_2_preview.aio.operations import KeyVaultClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.begin_full_backup(vault_base_url, azure_storage_blob_container_uri, **kwargs)

    async def begin_full_restore_operation(
        self,
        vault_base_url: str,
        restore_blob_details: Optional["models.RestoreOperationParameters"] = None,
        **kwargs
    ) -> AsyncLROPoller["models.RestoreOperation"]:
        """Restores all key materials using the SAS token pointing to a previously stored Azure Blob
        storage backup folder.

        :param vault_base_url: The vault name, for example https://myvault.vault.azure.net.
        :type vault_base_url: str
        :param restore_blob_details: The Azure blob SAS token pointing to a folder where the previous
         successful full backup was stored.
        :type restore_blob_details: ~azure.keyvault.v7_2.models.RestoreOperationParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either RestoreOperation or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.keyvault.v7_2.models.RestoreOperation]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        api_version = self._get_api_version('begin_full_restore_operation')
        if api_version == '7.2-preview':
            from ..v7_2_preview.aio.operations import KeyVaultClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.begin_full_restore_operation(vault_base_url, restore_blob_details, **kwargs)

    async def begin_selective_key_restore_operation(
        self,
        vault_base_url: str,
        key_name: str,
        restore_blob_details: Optional["models.SelectiveKeyRestoreOperationParameters"] = None,
        **kwargs
    ) -> AsyncLROPoller["models.SelectiveKeyRestoreOperation"]:
        """Restores all key versions of a given key using user supplied SAS token pointing to a previously
        stored Azure Blob storage backup folder.

        :param vault_base_url: The vault name, for example https://myvault.vault.azure.net.
        :type vault_base_url: str
        :param key_name: The name of the key to be restored from the user supplied backup.
        :type key_name: str
        :param restore_blob_details: The Azure blob SAS token pointing to a folder where the previous
         successful full backup was stored.
        :type restore_blob_details: ~azure.keyvault.v7_2.models.SelectiveKeyRestoreOperationParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either SelectiveKeyRestoreOperation or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.keyvault.v7_2.models.SelectiveKeyRestoreOperation]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        api_version = self._get_api_version('begin_selective_key_restore_operation')
        if api_version == '7.2-preview':
            from ..v7_2_preview.aio.operations import KeyVaultClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.begin_selective_key_restore_operation(vault_base_url, key_name, restore_blob_details, **kwargs)

    async def full_backup_status(
        self,
        vault_base_url: str,
        job_id: str,
        **kwargs
    ) -> "models.FullBackupOperation":
        """Returns the status of full backup operation.

        :param vault_base_url: The vault name, for example https://myvault.vault.azure.net.
        :type vault_base_url: str
        :param job_id: The id returned as part of the backup request.
        :type job_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: FullBackupOperation, or the result of cls(response)
        :rtype: ~azure.keyvault.v7_2.models.FullBackupOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('full_backup_status')
        if api_version == '7.2-preview':
            from ..v7_2_preview.aio.operations import KeyVaultClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.full_backup_status(vault_base_url, job_id, **kwargs)

    async def restore_status(
        self,
        vault_base_url: str,
        job_id: str,
        **kwargs
    ) -> "models.RestoreOperation":
        """Returns the status of restore operation.

        :param vault_base_url: The vault name, for example https://myvault.vault.azure.net.
        :type vault_base_url: str
        :param job_id: The Job Id returned part of the restore operation.
        :type job_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RestoreOperation, or the result of cls(response)
        :rtype: ~azure.keyvault.v7_2.models.RestoreOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('restore_status')
        if api_version == '7.2-preview':
            from ..v7_2_preview.aio.operations import KeyVaultClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.restore_status(vault_base_url, job_id, **kwargs)
