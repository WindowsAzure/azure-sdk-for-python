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

from .resource import Resource


class DeletedSite(Resource):
    """Reports deleted site including the timestamp of operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param deleted_timestamp: Time when the site was deleted
    :type deleted_timestamp: datetime
    :param deleted_site_name: Name of web app
    :type deleted_site_name: str
    :ivar state: State of the web app
    :vartype state: str
    :ivar host_names: Hostnames associated with web app
    :vartype host_names: list of str
    :ivar repository_site_name: Name of repository site
    :vartype repository_site_name: str
    :ivar usage_state: State indicating whether web app has exceeded its quota
     usage. Possible values include: 'Normal', 'Exceeded'
    :vartype usage_state: str or :class:`UsageState
     <azure.mgmt.web.models.UsageState>`
    :param enabled: True if the site is enabled; otherwise, false. Setting
     this  value to false disables the site (takes the site off line).
    :type enabled: bool
    :ivar enabled_host_names: Hostnames for the web app that are enabled.
     Hostnames need to be assigned and enabled. If some hostnames are assigned
     but not enabled
     the app is not served on those hostnames
    :vartype enabled_host_names: list of str
    :ivar availability_state: Management information availability state for
     the web app. Possible values are Normal or Limited.
     Normal means that the site is running correctly and that management
     information for the site is available.
     Limited means that only partial management information for the site is
     available and that detailed site information is unavailable. Possible
     values include: 'Normal', 'Limited', 'DisasterRecoveryMode'
    :vartype availability_state: str or :class:`SiteAvailabilityState
     <azure.mgmt.web.models.SiteAvailabilityState>`
    :param host_name_ssl_states: Hostname SSL states are  used to manage the
     SSL bindings for site's hostnames.
    :type host_name_ssl_states: list of :class:`HostNameSslState
     <azure.mgmt.web.models.HostNameSslState>`
    :param server_farm_id:
    :type server_farm_id: str
    :ivar last_modified_time_utc: Last time web app was modified in UTC
    :vartype last_modified_time_utc: datetime
    :param site_config: Configuration of web app
    :type site_config: :class:`SiteConfig <azure.mgmt.web.models.SiteConfig>`
    :ivar traffic_manager_host_names: Read-only list of Azure Traffic manager
     hostnames associated with web app
    :vartype traffic_manager_host_names: list of str
    :ivar premium_app_deployed: If set indicates whether web app is deployed
     as a premium app
    :vartype premium_app_deployed: bool
    :param scm_site_also_stopped: If set indicates whether to stop SCM (KUDU)
     site when the web app is stopped. Default is false.
    :type scm_site_also_stopped: bool
    :ivar target_swap_slot: Read-only property that specifies which slot this
     app will swap into
    :vartype target_swap_slot: str
    :param hosting_environment_profile: Specification for the hosting
     environment (App Service Environment) to use for the web app
    :type hosting_environment_profile: :class:`HostingEnvironmentProfile
     <azure.mgmt.web.models.HostingEnvironmentProfile>`
    :param micro_service:
    :type micro_service: str
    :param gateway_site_name: Name of gateway app associated with web app
    :type gateway_site_name: str
    :param client_affinity_enabled: Specifies if the client affinity is
     enabled when load balancing http request for multiple instances of the web
     app
    :type client_affinity_enabled: bool
    :param client_cert_enabled: Specifies if the client certificate is enabled
     for the web app
    :type client_cert_enabled: bool
    :param host_names_disabled: Specifies if the public hostnames are disabled
     the web app.
     If set to true the app is only accessible via API Management process
    :type host_names_disabled: bool
    :ivar outbound_ip_addresses: List of comma separated IP addresses that
     this web app uses for outbound connections. Those can be used when
     configuring firewall rules for databases accessed by this web app.
    :vartype outbound_ip_addresses: str
    :param container_size: Size of a function container
    :type container_size: int
    :param max_number_of_workers: Maximum number of workers
     This only applies to function container
    :type max_number_of_workers: int
    :param cloning_info: This is only valid for web app creation. If
     specified, web app is cloned from
     a source web app
    :type cloning_info: :class:`CloningInfo
     <azure.mgmt.web.models.CloningInfo>`
    :ivar resource_group: Resource group web app belongs to
    :vartype resource_group: str
    :ivar is_default_container: Site is a default container
    :vartype is_default_container: bool
    :ivar default_host_name: Default hostname of the web app
    :vartype default_host_name: str
    """

    _validation = {
        'location': {'required': True},
        'state': {'readonly': True},
        'host_names': {'readonly': True},
        'repository_site_name': {'readonly': True},
        'usage_state': {'readonly': True},
        'enabled_host_names': {'readonly': True},
        'availability_state': {'readonly': True},
        'last_modified_time_utc': {'readonly': True},
        'traffic_manager_host_names': {'readonly': True},
        'premium_app_deployed': {'readonly': True},
        'target_swap_slot': {'readonly': True},
        'outbound_ip_addresses': {'readonly': True},
        'resource_group': {'readonly': True},
        'is_default_container': {'readonly': True},
        'default_host_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'deleted_timestamp': {'key': 'properties.deletedTimestamp', 'type': 'iso-8601'},
        'deleted_site_name': {'key': 'properties.name', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'host_names': {'key': 'properties.hostNames', 'type': '[str]'},
        'repository_site_name': {'key': 'properties.repositorySiteName', 'type': 'str'},
        'usage_state': {'key': 'properties.usageState', 'type': 'UsageState'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'enabled_host_names': {'key': 'properties.enabledHostNames', 'type': '[str]'},
        'availability_state': {'key': 'properties.availabilityState', 'type': 'SiteAvailabilityState'},
        'host_name_ssl_states': {'key': 'properties.hostNameSslStates', 'type': '[HostNameSslState]'},
        'server_farm_id': {'key': 'properties.serverFarmId', 'type': 'str'},
        'last_modified_time_utc': {'key': 'properties.lastModifiedTimeUtc', 'type': 'iso-8601'},
        'site_config': {'key': 'properties.siteConfig', 'type': 'SiteConfig'},
        'traffic_manager_host_names': {'key': 'properties.trafficManagerHostNames', 'type': '[str]'},
        'premium_app_deployed': {'key': 'properties.premiumAppDeployed', 'type': 'bool'},
        'scm_site_also_stopped': {'key': 'properties.scmSiteAlsoStopped', 'type': 'bool'},
        'target_swap_slot': {'key': 'properties.targetSwapSlot', 'type': 'str'},
        'hosting_environment_profile': {'key': 'properties.hostingEnvironmentProfile', 'type': 'HostingEnvironmentProfile'},
        'micro_service': {'key': 'properties.microService', 'type': 'str'},
        'gateway_site_name': {'key': 'properties.gatewaySiteName', 'type': 'str'},
        'client_affinity_enabled': {'key': 'properties.clientAffinityEnabled', 'type': 'bool'},
        'client_cert_enabled': {'key': 'properties.clientCertEnabled', 'type': 'bool'},
        'host_names_disabled': {'key': 'properties.hostNamesDisabled', 'type': 'bool'},
        'outbound_ip_addresses': {'key': 'properties.outboundIpAddresses', 'type': 'str'},
        'container_size': {'key': 'properties.containerSize', 'type': 'int'},
        'max_number_of_workers': {'key': 'properties.maxNumberOfWorkers', 'type': 'int'},
        'cloning_info': {'key': 'properties.cloningInfo', 'type': 'CloningInfo'},
        'resource_group': {'key': 'properties.resourceGroup', 'type': 'str'},
        'is_default_container': {'key': 'properties.isDefaultContainer', 'type': 'bool'},
        'default_host_name': {'key': 'properties.defaultHostName', 'type': 'str'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, deleted_timestamp=None, deleted_site_name=None, enabled=None, host_name_ssl_states=None, server_farm_id=None, site_config=None, scm_site_also_stopped=None, hosting_environment_profile=None, micro_service=None, gateway_site_name=None, client_affinity_enabled=None, client_cert_enabled=None, host_names_disabled=None, container_size=None, max_number_of_workers=None, cloning_info=None):
        super(DeletedSite, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.deleted_timestamp = deleted_timestamp
        self.deleted_site_name = deleted_site_name
        self.state = None
        self.host_names = None
        self.repository_site_name = None
        self.usage_state = None
        self.enabled = enabled
        self.enabled_host_names = None
        self.availability_state = None
        self.host_name_ssl_states = host_name_ssl_states
        self.server_farm_id = server_farm_id
        self.last_modified_time_utc = None
        self.site_config = site_config
        self.traffic_manager_host_names = None
        self.premium_app_deployed = None
        self.scm_site_also_stopped = scm_site_also_stopped
        self.target_swap_slot = None
        self.hosting_environment_profile = hosting_environment_profile
        self.micro_service = micro_service
        self.gateway_site_name = gateway_site_name
        self.client_affinity_enabled = client_affinity_enabled
        self.client_cert_enabled = client_cert_enabled
        self.host_names_disabled = host_names_disabled
        self.outbound_ip_addresses = None
        self.container_size = container_size
        self.max_number_of_workers = max_number_of_workers
        self.cloning_info = cloning_info
        self.resource_group = None
        self.is_default_container = None
        self.default_host_name = None
