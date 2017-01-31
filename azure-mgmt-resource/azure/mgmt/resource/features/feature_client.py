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

from msrest.service_client import ServiceClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.features_operations import FeaturesOperations
from . import models


class FeatureClientConfiguration(AzureConfiguration):
    """Configuration for FeatureClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param api_version: The API version to use for this operation.
    :type api_version: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, api_version='2015-12-01', base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not isinstance(subscription_id, str):
            raise TypeError("Parameter 'subscription_id' must be str.")
        if api_version is not None and not isinstance(api_version, str):
            raise TypeError("Optional parameter 'api_version' must be str.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(FeatureClientConfiguration, self).__init__(base_url)

        self.add_user_agent('featureclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id
        self.api_version = api_version


class FeatureClient(object):
    """Azure Feature Exposure Control (AFEC) provides a mechanism for the resource providers to control feature exposure to users. Resource providers typically use this mechanism to provide public/private preview for new features prior to making them generally available. Users need to explicitly register for AFEC features to get access to such functionality.

    :ivar config: Configuration for client.
    :vartype config: FeatureClientConfiguration

    :ivar features: Features operations
    :vartype features: .operations.FeaturesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param api_version: The API version to use for this operation.
    :type api_version: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, api_version='2015-12-01', base_url=None):

        self.config = FeatureClientConfiguration(credentials, subscription_id, api_version, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.features = FeaturesOperations(
            self._client, self.config, self._serialize, self._deserialize)
