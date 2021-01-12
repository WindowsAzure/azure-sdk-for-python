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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import FormRecognizerClientConfiguration
from .operations import FormRecognizerClientOperationsMixin
from . import models


class FormRecognizerClient(FormRecognizerClientOperationsMixin, SDKClient):
    """Extracts information from forms and images into structured data.

    :ivar config: Configuration for client.
    :vartype config: FormRecognizerClientConfiguration

    :param endpoint: Supported Cognitive Services endpoints (protocol and
     hostname, for example: https://westus2.api.cognitive.microsoft.com).
    :type endpoint: str
    :param credentials: Subscription credentials which uniquely identify
     client subscription.
    :type credentials: None
    """

    def __init__(
            self, endpoint, credentials):

        self.config = FormRecognizerClientConfiguration(endpoint, credentials)
        super(FormRecognizerClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2.0'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

