# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import unittest

from azure.core.credentials import AccessToken
from azure.communication.sms import SmsClient
from unittest_helpers import mock_response

try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock  # type: ignore

class FakeTokenCredential(object):
    def __init__(self):
        self.token = AccessToken("Fake Token", 0)

    def get_token(self, *args):
        return self.token

class TestSMSClient(unittest.TestCase):
    def test_send_message(self):
        to_phone_number = "+18000005555"
        raised = False

        def mock_send(*_, **__):
            return mock_response(status_code=202, json_payload={
                "value": [
                    {
                        "to": to_phone_number,
                        "messageId": "id",
                        "httpStatusCode": "202",
                        "errorMessage": "null",
                        "repeatabilityResult": "accepted",
                        "successful": "true"
                    }
                ]
            })
            
        sms_client = SmsClient("https://endpoint", FakeTokenCredential(), transport=Mock(send=mock_send))

        sms_response = None
        try:
            sms_responses = sms_client.send(
                from_="+18000005554",
                to=[to_phone_number],
                message="Hello World via SMS",
                enable_delivery_report=True,
                tag="custom-tag")
            sms_response = sms_responses[0]
        except:
            raised = True
            raise

        self.assertFalse(raised, 'Expected is no excpetion raised')
        self.assertEqual(to_phone_number, sms_response.to)
        self.assertIsNotNone(sms_response.message_id)
        self.assertEqual(202, sms_response.http_status_code)
        self.assertIsNotNone(sms_response.error_message)
        self.assertTrue(sms_response.successful)
