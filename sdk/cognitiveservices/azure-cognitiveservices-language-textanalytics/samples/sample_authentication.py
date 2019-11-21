# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_authentication.py

DESCRIPTION:
    This sample demonstrates how to authenticate with the text analytics service.

    There are two supported methods of authentication:
    1) Use a cognitive services subscription key
    2) Use a token credential from Azure Active Directory

    See more details about authentication here:
    https://docs.microsoft.com/azure/cognitive-services/authentication

USAGE:
    python sample_authentication.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_TEXT_ANALYTICS_ENDPOINT - the endpoint to your cognitive services resource.
    2) AZURE_COGNITIVE_SERVICES_KEY - your cognitive services account key
    3) AZURE_AAD_CLIENT_ID - the client ID of your active directory application.
    4) AZURE_AAD_TENANT_ID - the tenant ID of your active directory application.
    5) AZURE_AAD_SECRET - the secret of your active directory application.
"""

import os


class AuthenticationSample(object):

    endpoint = os.getenv("AZURE_TEXT_ANALYTICS_ENDPOINT")
    key = os.getenv("AZURE_COGNITIVE_SERVICES_KEY")
    client_id = os.getenv("AZURE_AAD_CLIENT_ID")
    tenant_id = os.getenv("AZURE_AAD_TENANT_ID")
    client_secret = os.getenv("AZURE_AAD_SECRET")

    def authentication_with_subscription_key(self):
        from azure.cognitiveservices.language.textanalytics import TextAnalyticsClient
        text_analytics_client = TextAnalyticsClient(self.endpoint, self.key)

        doc = ["I need to take my cat to the veterinarian."]
        result = text_analytics_client.detect_language(doc)

        print("Language detected: {}".format(result[0].detected_language.name))
        print("Confidence score: {}".format(result[0].detected_language.score))

    def authentication_with_azure_active_directory(self):
        from azure.cognitiveservices.language.textanalytics import TextAnalyticsClient
        from azure.identity import ClientSecretCredential

        token = ClientSecretCredential(
            client_id=self.client_id,
            tenant_id=self.tenant_id,
            client_secret=self.client_secret
        )

        text_analytics_client = TextAnalyticsClient(self.endpoint, credential=token)
        doc = ["I need to take my cat to the veterinarian."]
        result = text_analytics_client.detect_language(doc)

        print("Language detected: {}".format(result[0].detected_language.name))
        print("Confidence score: {}".format(result[0].detected_language.score))


if __name__ == '__main__':
    sample = AuthenticationSample()
    sample.authentication_with_subscription_key()
    sample.authentication_with_azure_active_directory()
