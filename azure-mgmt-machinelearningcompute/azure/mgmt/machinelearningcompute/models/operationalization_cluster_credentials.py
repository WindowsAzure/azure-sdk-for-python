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

from msrest.serialization import Model


class OperationalizationClusterCredentials(Model):
    """Credentials to resources in the cluster.

    :param storage_account: Credentials for the Storage Account.
    :type storage_account:
     ~azure.mgmt.machinelearningcompute.models.StorageAccountCredentials
    :param container_registry: Credentials for Azure Container Registry.
    :type container_registry:
     ~azure.mgmt.machinelearningcompute.models.ContainerRegistryCredentials
    :param container_service: Credentials for Azure Container Service.
    :type container_service:
     ~azure.mgmt.machinelearningcompute.models.ContainerServiceCredentials
    :param app_insights: Credentials for Azure AppInsights.
    :type app_insights:
     ~azure.mgmt.machinelearningcompute.models.AppInsightsCredentials
    :param service_auth_configuration: Global authorization keys for all user
     services deployed in cluster. These are used if the service does not have
     auth keys.
    :type service_auth_configuration:
     ~azure.mgmt.machinelearningcompute.models.ServiceAuthConfiguration
    :param ssl_configuration: The SSL configuration for the services.
    :type ssl_configuration:
     ~azure.mgmt.machinelearningcompute.models.SslConfiguration
    """

    _attribute_map = {
        'storage_account': {'key': 'storageAccount', 'type': 'StorageAccountCredentials'},
        'container_registry': {'key': 'containerRegistry', 'type': 'ContainerRegistryCredentials'},
        'container_service': {'key': 'containerService', 'type': 'ContainerServiceCredentials'},
        'app_insights': {'key': 'appInsights', 'type': 'AppInsightsCredentials'},
        'service_auth_configuration': {'key': 'serviceAuthConfiguration', 'type': 'ServiceAuthConfiguration'},
        'ssl_configuration': {'key': 'sslConfiguration', 'type': 'SslConfiguration'},
    }

    def __init__(self, storage_account=None, container_registry=None, container_service=None, app_insights=None, service_auth_configuration=None, ssl_configuration=None):
        super(OperationalizationClusterCredentials, self).__init__()
        self.storage_account = storage_account
        self.container_registry = container_registry
        self.container_service = container_service
        self.app_insights = app_insights
        self.service_auth_configuration = service_auth_configuration
        self.ssl_configuration = ssl_configuration
