#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#-------------------------------------------------------------------------

import logging
import sys
import os
import pytest
import time
from datetime import datetime, timedelta

from azure.servicebus import Message, PeekMessage, ReceiveSettleMode
from azure.servicebus.aio import ServiceBusClient, ServiceBusSharedKeyCredential
from azure.servicebus.exceptions import ServiceBusError

from devtools_testutils import AzureMgmtTestCase, RandomNameResourceGroupPreparer, CachedResourceGroupPreparer
from servicebus_preparer import (
    CachedServiceBusNamespacePreparer,
    CachedServiceBusTopicPreparer,
    CachedServiceBusSubscriptionPreparer,
    ServiceBusTopicPreparer,
    ServiceBusSubscriptionPreparer
)
from utilities import get_logger, print_message

_logger = get_logger(logging.DEBUG)


class ServiceBusSubscriptionAsyncTests(AzureMgmtTestCase):
    @pytest.mark.liveTest
    @pytest.mark.live_test_only
    @CachedResourceGroupPreparer(name_prefix='servicebustest')
    @CachedServiceBusNamespacePreparer(name_prefix='servicebustest')
    @ServiceBusTopicPreparer(name_prefix='servicebustest')
    @ServiceBusSubscriptionPreparer(name_prefix='servicebustest')
    async def test_subscription_by_subscription_client_conn_str_receive_basic(self, servicebus_namespace_connection_string, servicebus_topic, servicebus_subscription, **kwargs):

        async with ServiceBusClient.from_connection_string(
                servicebus_namespace_connection_string,
                logging_enable=False
        ) as sb_client:
            async with sb_client.get_topic_sender(topic_name=servicebus_topic.name) as sender:
                message = Message(b"Sample topic message")
                await sender.send(message)

            async with sb_client.get_subscription_receiver(
                    topic_name=servicebus_topic.name,
                    subscription_name=servicebus_subscription.name,
                    idle_timeout=5
            ) as receiver:
                count = 0
                async for message in receiver:
                    count += 1
                    await message.complete()
            assert count == 1

    @pytest.mark.liveTest
    @pytest.mark.live_test_only
    @CachedResourceGroupPreparer(name_prefix='servicebustest')
    @CachedServiceBusNamespacePreparer(name_prefix='servicebustest')
    @ServiceBusTopicPreparer(name_prefix='servicebustest')
    @ServiceBusSubscriptionPreparer(name_prefix='servicebustest')
    async def test_subscription_by_sas_token_credential_conn_str_send_basic(self, servicebus_namespace, servicebus_namespace_key_name, servicebus_namespace_primary_key, servicebus_topic, servicebus_subscription, **kwargs):
        fully_qualified_namespace = servicebus_namespace.name + '.servicebus.windows.net'
        async with ServiceBusClient(
            fully_qualified_namespace=fully_qualified_namespace,
            credential=ServiceBusSharedKeyCredential(
                policy=servicebus_namespace_key_name,
                key=servicebus_namespace_primary_key
            ),
            logging_enable=False
        ) as sb_client:

            async with sb_client.get_topic_sender(topic_name=servicebus_topic.name) as sender:
                message = Message(b"Sample topic message")
                await sender.send(message)

            async with sb_client.get_subscription_receiver(
                    topic_name=servicebus_topic.name,
                    subscription_name=servicebus_subscription.name,
                    idle_timeout=5
            ) as receiver:
                count = 0
                async for message in receiver:
                    count += 1
                    await message.complete()
            assert count == 1
