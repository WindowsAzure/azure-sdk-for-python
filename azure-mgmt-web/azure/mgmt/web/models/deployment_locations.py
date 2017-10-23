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


class DeploymentLocations(Model):
    """List of available locations (regions or App Service Environments) for
    deployment of App Service resources.

    :param locations: Available regions.
    :type locations: list[~azure.mgmt.web.models.GeoRegion]
    :param hosting_environments: Available App Service Environments with full
     descriptions of the environments.
    :type hosting_environments:
     list[~azure.mgmt.web.models.AppServiceEnvironment]
    :param hosting_environment_deployment_infos: Available App Service
     Environments with basic information.
    :type hosting_environment_deployment_infos:
     list[~azure.mgmt.web.models.HostingEnvironmentDeploymentInfo]
    """

    _attribute_map = {
        'locations': {'key': 'locations', 'type': '[GeoRegion]'},
        'hosting_environments': {'key': 'hostingEnvironments', 'type': '[AppServiceEnvironment]'},
        'hosting_environment_deployment_infos': {'key': 'hostingEnvironmentDeploymentInfos', 'type': '[HostingEnvironmentDeploymentInfo]'},
    }

    def __init__(self, locations=None, hosting_environments=None, hosting_environment_deployment_infos=None):
        self.locations = locations
        self.hosting_environments = hosting_environments
        self.hosting_environment_deployment_infos = hosting_environment_deployment_infos
