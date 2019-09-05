# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from typing import Iterable, Dict, Any
import logging
from collections import defaultdict
import asyncio
from azure.eventhub.aio.eventprocessor import PartitionManager, OwnershipLostError
from azure.core.exceptions import ResourceModifiedError, ResourceExistsError, AzureError
from azure.storage.blob.aio import ContainerClient

logger = logging.getLogger(__name__)
UPLOAD_DATA = ""


class BlobPartitionManager(PartitionManager):
    """An PartitionManager that uses Azure Blob Storage to store the partition ownership and checkpoint data.

    This class implements methods list_ownership, claim_ownership, and update_checkpoint that are defined in class
    azure.eventhub.eventprocessor.PartitionManager of package azure-eventhub.

    """
    def __init__(self, container_client: ContainerClient):
        """

        :param container_client: The Azure Blob Storage Container client.
        """
        self._container_client = container_client
        self._cached_ownership_dict = defaultdict(dict)  # type: Dict[str, Dict[str, Any]]
        # lock each partition for list_ownership, claim_ownership and update_checkpoint etag doesn't get out of sync
        # when the three methods are running concurrently
        self._cached_ownership_locks = defaultdict(asyncio.Lock)

    async def list_ownership(self, eventhub_name: str, consumer_group_name: str) -> Iterable[Dict[str, Any]]:
        try:
            blobs = self._container_client.list_blobs(include=['metadata'])
        except Exception as err:  # pylint:disable=broad-except
            logger.warning("An exception occurred during list_ownership for eventhub %r consumer group %r. "
                           "Exception is %r", eventhub_name, consumer_group_name, err)
            raise
        async for b in blobs:  # TODO: running them concurrently
            async with self._cached_ownership_locks[b.name]:
                metadata = b.metadata
                ownership = {
                    "eventhub_name": eventhub_name,
                    "consumer_group_name": consumer_group_name,
                    "partition_id": b.name,
                    "owner_id": metadata["owner_id"],
                    "etag": b.etag,
                    "last_modified_time": b.last_modified.timestamp() if b.last_modified else None
                }
                ownership.update(metadata)
                self._cached_ownership_dict[b.name] = ownership
        return self._cached_ownership_dict.values()

    async def claim_ownership(self, ownership_list: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
        result = []
        for ownership in ownership_list:  # TODO: claiming concurrently
            partition_id = ownership["partition_id"]
            eventhub_name = ownership["eventhub_name"]
            consumer_group_name = ownership["consumer_group_name"]
            owner_id = ownership["owner_id"]

            async with self._cached_ownership_locks[partition_id]:
                metadata = {"owner_id": ownership["owner_id"]}
                if "offset" in ownership:
                    metadata["offset"] = ownership["offset"]
                if "sequence_number" in ownership:
                    metadata["sequence_number"] = ownership["sequence_number"]

                etag = ownership.get("etag")
                if etag:
                    etag_match = {"if_match": '"'+etag+'"'}
                else:
                    etag_match = {"if_none_match": '*'}
                try:
                    blob_client = await self._container_client.upload_blob(
                        name=partition_id, data=UPLOAD_DATA, overwrite=True, metadata=metadata, **etag_match
                    )
                    uploaded_blob_properties = await blob_client.get_blob_properties()
                    ownership["etag"] = uploaded_blob_properties.etag
                    ownership["last_modified_time"] = uploaded_blob_properties.last_modified.timestamp()
                    self._cached_ownership_dict[partition_id] = ownership
                    result.append(ownership)
                except (ResourceModifiedError, ResourceExistsError):
                    logger.info(
                        "EventProcessor instance %r of eventhub %r consumer group %r lost ownership to partition %r",
                        owner_id, eventhub_name, consumer_group_name, partition_id)
                except Exception as err:
                    logger.warning("An exception occurred when EventProcessor instance %r claim_ownership for "
                                   "eventhub %r consumer group %r partition %r. The ownership is now lost. Exception "
                                   "is %r", owner_id, eventhub_name, consumer_group_name, partition_id, err)

        return result

    async def update_checkpoint(self, eventhub_name, consumer_group_name, partition_id, owner_id,
                                offset, sequence_number) -> None:

        metadata = {
            "owner_id": owner_id,
            "offset": offset,
            "sequence_number": str(sequence_number)
        }
        async with self._cached_ownership_locks[partition_id]:
            try:
                blob_client = await self._container_client.upload_blob(
                    name=partition_id, data=UPLOAD_DATA, metadata=metadata, overwrite=True)
                uploaded_blob_properties = await blob_client.get_blob_properties()
                cached_ownership = self._cached_ownership_dict[partition_id]
                cached_ownership["etag"] = uploaded_blob_properties.etag
                cached_ownership["last_modified_time"] = uploaded_blob_properties.last_modified.timestamp()
            except (ResourceModifiedError, ResourceExistsError):
                logger.info(
                    "EventProcessor instance %r of eventhub %r consumer group %r couldn't update_checkpoint to "
                    "partition %r because the ownership has been stolen",
                    owner_id, eventhub_name, consumer_group_name, partition_id)
                raise OwnershipLostError()
            except Exception as err:
                logger.warning(
                    "EventProcessor instance %r of eventhub %r consumer group %r couldn't update_checkpoint to "
                    "partition %r because of unexpected error. Exception is",
                    owner_id, eventhub_name, consumer_group_name, partition_id, err)
                raise  # EventProcessor will catch the exception and handle it
