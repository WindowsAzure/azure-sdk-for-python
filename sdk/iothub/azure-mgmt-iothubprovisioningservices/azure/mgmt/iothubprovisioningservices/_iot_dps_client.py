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

from ._configuration import IotDpsClientConfiguration
from .operations import Operations
from .operations import DpsCertificateOperations
from .operations import IotDpsResourceOperations
from . import models


class IotDpsClient(SDKClient):
    """API for using the Azure IoT Hub Device Provisioning Service features.

    :ivar config: Configuration for client.
    :vartype config: IotDpsClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.iothubprovisioningservices.operations.Operations
    :ivar dps_certificate: DpsCertificate operations
    :vartype dps_certificate: azure.mgmt.iothubprovisioningservices.operations.DpsCertificateOperations
    :ivar iot_dps_resource: IotDpsResource operations
    :vartype iot_dps_resource: azure.mgmt.iothubprovisioningservices.operations.IotDpsResourceOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription identifier.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = IotDpsClientConfiguration(credentials, subscription_id, base_url)
        super(IotDpsClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2020-09-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.dps_certificate = DpsCertificateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.iot_dps_resource = IotDpsResourceOperations(
            self._client, self.config, self._serialize, self._deserialize)
