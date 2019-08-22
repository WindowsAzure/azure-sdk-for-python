# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# -----------------------------------------------------------------------------------

from typing import List
from typing_extensions import Protocol
from enum import Enum
from .checkpoint_manager import CheckpointManager

from azure.eventhub import EventData


class CloseReason(Enum):
    SHUTDOWN = 0  # user call EventProcessor.stop()
    OWNERSHIP_LOST = 1  # lose the ownership of a partition.
    EVENTHUB_EXCEPTION = 2  # Exception happens during receiving events


class PartitionProcessor(Protocol):
    """
    PartitionProcessor processes events received from the Azure Event Hubs service. A single instance of a class
    implementing this abstract class will be created for every partition the associated ~azure.eventhub.eventprocessor.EventProcessor owns.

    """
    async def initialize(self, checkpoint_manager: CheckpointManager):
        pass

    async def close(self, reason, checkpoint_manager: CheckpointManager):
        """Called when EventProcessor stops processing this PartitionProcessor.

        There are different reasons to trigger the PartitionProcessor to close.
        Refer to enum class ~azure.eventhub.eventprocessor.CloseReason

        :param reason: Reason for closing the PartitionProcessor.
        :type reason: ~azure.eventhub.eventprocessor.CloseReason

        """
        pass

    async def process_events(self, events: List[EventData], checkpoint_manager: CheckpointManager):
        """Called when a batch of events have been received.

        :param events: Received events.
        :type events: list[~azure.eventhub.common.EventData]

        """
        pass

    async def process_error(self, error, checkpoint_manager: CheckpointManager):
        """Called when an error happens

        :param error: The error that happens.
        :type error: Exception

        """
        pass
