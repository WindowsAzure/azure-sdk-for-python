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

from .proxy_only_resource import ProxyOnlyResource


class AppServicePlanPatchResource(ProxyOnlyResource):
    """ARM resource for a app service plan.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param app_service_plan_patch_resource_name: Name for the App Service
     plan.
    :type app_service_plan_patch_resource_name: str
    :param worker_tier_name: Target worker tier assigned to the App Service
     plan.
    :type worker_tier_name: str
    :ivar status: App Service plan status. Possible values include: 'Ready',
     'Pending', 'Creating'
    :vartype status: str or ~azure.mgmt.web.models.StatusOptions
    :ivar subscription: App Service plan subscription.
    :vartype subscription: str
    :param admin_site_name: App Service plan administration site.
    :type admin_site_name: str
    :param hosting_environment_profile: Specification for the App Service
     Environment to use for the App Service plan.
    :type hosting_environment_profile:
     ~azure.mgmt.web.models.HostingEnvironmentProfile
    :ivar maximum_number_of_workers: Maximum number of instances that can be
     assigned to this App Service plan.
    :vartype maximum_number_of_workers: int
    :ivar geo_region: Geographical location for the App Service plan.
    :vartype geo_region: str
    :param per_site_scaling: If <code>true</code>, apps assigned to this App
     Service plan can be scaled independently.
     If <code>false</code>, apps assigned to this App Service plan will scale
     to all instances of the plan. Default value: False .
    :type per_site_scaling: bool
    :ivar number_of_sites: Number of apps assigned to this App Service plan.
    :vartype number_of_sites: int
    :param is_spot: If <code>true</code>, this App Service Plan owns spot
     instances.
    :type is_spot: bool
    :param spot_expiration_time: The time when the server farm expires. Valid
     only if it is a spot server farm.
    :type spot_expiration_time: datetime
    :ivar resource_group: Resource group of the App Service plan.
    :vartype resource_group: str
    :param reserved: Reserved. Default value: False .
    :type reserved: bool
    :param target_worker_count: Scaling worker count.
    :type target_worker_count: int
    :param target_worker_size_id: Scaling worker size ID.
    :type target_worker_size_id: int
    :ivar provisioning_state: Provisioning state of the App Service
     Environment. Possible values include: 'Succeeded', 'Failed', 'Canceled',
     'InProgress', 'Deleting'
    :vartype provisioning_state: str or
     ~azure.mgmt.web.models.ProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'status': {'readonly': True},
        'subscription': {'readonly': True},
        'maximum_number_of_workers': {'readonly': True},
        'geo_region': {'readonly': True},
        'number_of_sites': {'readonly': True},
        'resource_group': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'app_service_plan_patch_resource_name': {'key': 'properties.name', 'type': 'str'},
        'worker_tier_name': {'key': 'properties.workerTierName', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'StatusOptions'},
        'subscription': {'key': 'properties.subscription', 'type': 'str'},
        'admin_site_name': {'key': 'properties.adminSiteName', 'type': 'str'},
        'hosting_environment_profile': {'key': 'properties.hostingEnvironmentProfile', 'type': 'HostingEnvironmentProfile'},
        'maximum_number_of_workers': {'key': 'properties.maximumNumberOfWorkers', 'type': 'int'},
        'geo_region': {'key': 'properties.geoRegion', 'type': 'str'},
        'per_site_scaling': {'key': 'properties.perSiteScaling', 'type': 'bool'},
        'number_of_sites': {'key': 'properties.numberOfSites', 'type': 'int'},
        'is_spot': {'key': 'properties.isSpot', 'type': 'bool'},
        'spot_expiration_time': {'key': 'properties.spotExpirationTime', 'type': 'iso-8601'},
        'resource_group': {'key': 'properties.resourceGroup', 'type': 'str'},
        'reserved': {'key': 'properties.reserved', 'type': 'bool'},
        'target_worker_count': {'key': 'properties.targetWorkerCount', 'type': 'int'},
        'target_worker_size_id': {'key': 'properties.targetWorkerSizeId', 'type': 'int'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningState'},
    }

    def __init__(self, kind=None, app_service_plan_patch_resource_name=None, worker_tier_name=None, admin_site_name=None, hosting_environment_profile=None, per_site_scaling=False, is_spot=None, spot_expiration_time=None, reserved=False, target_worker_count=None, target_worker_size_id=None):
        super(AppServicePlanPatchResource, self).__init__(kind=kind)
        self.app_service_plan_patch_resource_name = app_service_plan_patch_resource_name
        self.worker_tier_name = worker_tier_name
        self.status = None
        self.subscription = None
        self.admin_site_name = admin_site_name
        self.hosting_environment_profile = hosting_environment_profile
        self.maximum_number_of_workers = None
        self.geo_region = None
        self.per_site_scaling = per_site_scaling
        self.number_of_sites = None
        self.is_spot = is_spot
        self.spot_expiration_time = spot_expiration_time
        self.resource_group = None
        self.reserved = reserved
        self.target_worker_count = target_worker_count
        self.target_worker_size_id = target_worker_size_id
        self.provisioning_state = None
