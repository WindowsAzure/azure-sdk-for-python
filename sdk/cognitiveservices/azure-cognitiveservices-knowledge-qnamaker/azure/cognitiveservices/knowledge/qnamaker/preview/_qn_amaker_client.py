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

from ._configuration import QnAMakerClientConfiguration
from .operations import EndpointSettingsOperations
from .operations import EndpointKeysOperations
from .operations import AlterationsOperations
from .operations import KnowledgebaseOperations
from .operations import Operations
from .operations import PrebuiltOperations
from . import models


class QnAMakerClient(SDKClient):
    """An API for QnAMaker Service

    :ivar config: Configuration for client.
    :vartype config: QnAMakerClientConfiguration

    :ivar endpoint_settings: EndpointSettings operations
    :vartype endpoint_settings: azure.cognitiveservices.knowledge.qnamaker.preview.operations.EndpointSettingsOperations
    :ivar endpoint_keys: EndpointKeys operations
    :vartype endpoint_keys: azure.cognitiveservices.knowledge.qnamaker.preview.operations.EndpointKeysOperations
    :ivar alterations: Alterations operations
    :vartype alterations: azure.cognitiveservices.knowledge.qnamaker.preview.operations.AlterationsOperations
    :ivar knowledgebase: Knowledgebase operations
    :vartype knowledgebase: azure.cognitiveservices.knowledge.qnamaker.preview.operations.KnowledgebaseOperations
    :ivar operations: Operations operations
    :vartype operations: azure.cognitiveservices.knowledge.qnamaker.preview.operations.Operations
    :ivar prebuilt: Prebuilt operations
    :vartype prebuilt: azure.cognitiveservices.knowledge.qnamaker.preview.operations.PrebuiltOperations

    :param endpoint: Supported Cognitive Services endpoint (e.g., https://<
     qnamaker-resource-name >.api.cognitiveservices.azure.com).
    :type endpoint: str
    :param credentials: Subscription credentials which uniquely identify
     client subscription.
    :type credentials: None
    """

    def __init__(
            self, endpoint, credentials):

        self.config = QnAMakerClientConfiguration(endpoint, credentials)
        super(QnAMakerClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = 'v5.0-preview.2'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.endpoint_settings = EndpointSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.endpoint_keys = EndpointKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alterations = AlterationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.knowledgebase = KnowledgebaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.prebuilt = PrebuiltOperations(
            self._client, self.config, self._serialize, self._deserialize)
