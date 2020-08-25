#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
Example to demonstrate utilizing SAS (Shared Access Signature) tokens to authenticate with ServiceBus
"""

# pylint: disable=C0111

import os
import time
import hmac
import hashlib
import base64
try:
    from urllib.parse import quote as url_parse_quote
except ImportError:
    from urllib import pathname2url as url_parse_quote

from azure.core.credentials import AccessToken
from azure.eventhub import EventHubConsumerClient


def generate_sas_token(uri, sas_name, sas_value, token_ttl):
    """Performs the signing and encoding needed to generate a sas token from a sas key."""
    sas = sas_value.encode('utf-8')
    expiry = str(int(time.time() + token_ttl))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    signature = url_parse_quote(base64.b64encode(signed_hmac_sha256.digest()))
    return 'SharedAccessSignature sr={}&sig={}&se={}&skn={}'.format(uri, signature, expiry, sas_name)


class CustomizedSASCredential(object):
    def __init__(self, token, expiry):
        """
        :param str token: The token string
        :param float expiry: The epoch timestamp

        """
        self.token = token
        self.expiry = expiry
        self.token_type = b"servicebus.windows.net:sastoken"

    def get_token(self, *scopes, **kwargs):
        """
        This method is automatically called when token is about to expire.
        """
        return AccessToken(self.token, self.expiry)


# Target namespace and hub must also be specified.  Consumer group is set to default unless required otherwise.
FULLY_QUALIFIED_NAMESPACE = os.environ['EVENT_HUB_HOSTNAME']
EVENTHUB_NAME = os.environ['EVENT_HUB_NAME']
CONSUMER_GROUP = "$Default"

# The following part creates a SAS token. Users can use any way to create a SAS token.
SAS_POLICY = os.environ['EVENT_HUB_SAS_POLICY']
SAS_KEY = os.environ['EVENT_HUB_SAS_KEY']

uri = "sb://{}/{}".format(FULLY_QUALIFIED_NAMESPACE, EVENTHUB_NAME)
token_ttl = 3000  # seconds
sas_token = generate_sas_token(uri, SAS_POLICY, SAS_KEY, token_ttl)
# end of creating a SAS token

consumer_client = EventHubConsumerClient(
    fully_qualified_namespace=FULLY_QUALIFIED_NAMESPACE,
    eventhub_name=EVENTHUB_NAME,
    consumer_group=CONSUMER_GROUP,
    credential=CustomizedSASCredential(sas_token, time.time() + token_ttl),
    logging_enable=True
)

with consumer_client:
    consumer_client.receive(
        lambda pc, event: print(pc.partition_id, ":", event),
        starting_position=-1
    )
