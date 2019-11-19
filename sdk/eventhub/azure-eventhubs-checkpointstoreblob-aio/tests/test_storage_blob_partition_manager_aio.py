#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import pytest
import time
import os
import uuid
import warnings
import asyncio

from azure.eventhub.extensions.checkpointstoreblobaio import BlobPartitionManager


def get_live_storage_blob_client():
    try:
        storage_connection_str = os.environ['AZURE_STORAGE_CONN_STR']
    except KeyError:
        return None, None
    try:
        from azure.storage.blob import BlobServiceClient
        from azure.storage.blob.aio import ContainerClient
    except ImportError or ModuleNotFoundError:
        return None, None

    container_str = str(uuid.uuid4())
    blob_service_client = BlobServiceClient.from_connection_string(storage_connection_str)
    blob_service_client.create_container(container_str)
    container_client = ContainerClient.from_connection_string(storage_connection_str, container_str)
    return container_str, container_client


def remove_live_storage_blob_client(container_str):
    try:
        storage_connection_str = os.environ['AZURE_STORAGE_CONN_STR']
        from azure.storage.blob import BlobServiceClient
        blob_service_client = BlobServiceClient.from_connection_string(storage_connection_str)
        blob_service_client.delete_container(container_str)
    except:
        warnings.warn(UserWarning("storage container teardown failed"))


async def _claim_and_list_ownership(live_storage_blob_client):
    fully_qualified_namespace = 'test_namespace'
    eventhub_name = 'eventhub'
    consumer_group = '$default'
    ownership_cnt = 8
    async with live_storage_blob_client:
        partition_manager = BlobPartitionManager(container_client=live_storage_blob_client)

        ownership_list = await partition_manager.list_ownership(
            fully_qualified_namespace=fully_qualified_namespace,
            eventhub_name=eventhub_name,
            consumer_group=consumer_group)
        assert len(ownership_list) == 0

        ownership_list = []

        for i in range(ownership_cnt):
            ownership = {}
            ownership['fully_qualified_namespace'] = fully_qualified_namespace
            ownership['eventhub_name'] = eventhub_name
            ownership['consumer_group'] = consumer_group
            ownership['owner_id'] = 'ownerid'
            ownership['partition_id'] = str(i)
            ownership['last_modified_time'] = time.time()
            ownership_list.append(ownership)

        await partition_manager.claim_ownership(ownership_list)

        ownership_list = await partition_manager.list_ownership(
            fully_qualified_namespace=fully_qualified_namespace,
            eventhub_name=eventhub_name,
            consumer_group=consumer_group)
        assert len(ownership_list) == ownership_cnt


@pytest.mark.liveTest
def test_claim_and_list_ownership():
    container_str, live_storage_blob_client = get_live_storage_blob_client()
    if not live_storage_blob_client:
        pytest.skip("Storage blob client can't be created")
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_claim_and_list_ownership(live_storage_blob_client))
    finally:
        remove_live_storage_blob_client(container_str)


async def _update_checkpoint(live_storage_blob_client):
    fully_qualified_namespace = 'test_namespace'
    eventhub_name = 'eventhub'
    consumer_group = '$default'
    partition_cnt = 8

    async with live_storage_blob_client:
        partition_manager = BlobPartitionManager(container_client=live_storage_blob_client)
        for i in range(partition_cnt):
            await partition_manager.update_checkpoint(
                fully_qualified_namespace, eventhub_name, consumer_group, str(i),
                '2', 20)

        checkpoint_list = await partition_manager.list_checkpoints(
            fully_qualified_namespace=fully_qualified_namespace,
            eventhub_name=eventhub_name,
            consumer_group=consumer_group)
        assert len(checkpoint_list) == partition_cnt
        for checkpoint in checkpoint_list:
            assert checkpoint['offset'] == '2'
            assert checkpoint['sequence_number'] == '20'


@pytest.mark.liveTest
def test_update_checkpoint():
    container_str, live_storage_blob_client = get_live_storage_blob_client()
    if not live_storage_blob_client:
        pytest.skip("Storage blob client can't be created")
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_update_checkpoint(live_storage_blob_client))
    finally:
        remove_live_storage_blob_client(container_str)
