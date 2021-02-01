# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import os
import pytest
from azure.core.credentials import AccessToken
from azure.communication.sms.aio import SmsClient
from azure.communication.sms import (
    PhoneNumberIdentifier, SendSmsOptions
)
from azure.communication.sms._shared.utils import parse_connection_str
from _shared.asynctestcase import AsyncCommunicationTestCase
from _shared.testcase import (
    BodyReplacerProcessor, ResponseReplacerProcessor
)
from azure.identity import DefaultAzureCredential


class FakeTokenCredential(object):
    def __init__(self):
        self.token = AccessToken("Fake Token", 0)

    def get_token(self, *args):
        return self.token
class SMSClientTestAsync(AsyncCommunicationTestCase):
    def __init__(self, method_name):
        super(SMSClientTestAsync, self).__init__(method_name)

    def setUp(self):
        super(SMSClientTestAsync, self).setUp()

        if self.is_playback():
            self.phone_number = "+18000005555"
        else:
            self.phone_number = os.getenv("AZURE_COMMUNICATION_SERVICE_PHONE_NUMBER")

        self.recording_processors.extend([
            BodyReplacerProcessor(keys=["to", "from", "messageId"]),
            ResponseReplacerProcessor(keys=[self._resource_name])])

    @AsyncCommunicationTestCase.await_prepared_test
    @pytest.mark.live_test_only
    async def test_send_sms_async(self):

        sms_client = SmsClient.from_connection_string(self.connection_str)

        async with sms_client:
            # calling send() with sms values
            sms_response = await sms_client.send(
                from_phone_number=PhoneNumberIdentifier(self.phone_number),
                to_phone_numbers=[PhoneNumberIdentifier(self.phone_number)],
                message="Hello World via SMS",
                send_sms_options=SendSmsOptions(enable_delivery_report=True))  # optional property

            assert sms_response.message_id is not None

    @AsyncCommunicationTestCase.await_prepared_test
    @pytest.mark.live_test_only
    async def test_send_sms_async_from_managed_identity(self):
        endpoint, access_key = parse_connection_str(self.connection_str)
        from devtools_testutils import is_live
        if not is_live():
            credential = FakeTokenCredential()
        else:
            credential = DefaultAzureCredential()
        sms_client = SmsClient(endpoint, credential)
        print(sms_client)
        async with sms_client:
            # calling send() with sms values
            sms_response = await sms_client.send(
                from_phone_number=PhoneNumberIdentifier(self.phone_number),
                to_phone_numbers=[PhoneNumberIdentifier(self.phone_number)],
                message="Hello World via SMS",
                send_sms_options=SendSmsOptions(enable_delivery_report=True))  # optional property

            assert sms_response.message_id is not None
