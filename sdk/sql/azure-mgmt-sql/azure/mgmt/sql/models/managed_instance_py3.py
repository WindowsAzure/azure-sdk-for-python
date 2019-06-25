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

from .tracked_resource_py3 import TrackedResource


class ManagedInstance(TrackedResource):
    """An Azure SQL managed instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Required. Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param identity: The Azure Active Directory identity of the managed
     instance.
    :type identity: ~azure.mgmt.sql.models.ResourceIdentity
    :param sku: Managed instance SKU. Allowed values for sku.name: GP_Gen4,
     GP_Gen5, BC_Gen4, BC_Gen5
    :type sku: ~azure.mgmt.sql.models.Sku
    :param managed_instance_create_mode: Specifies the mode of database
     creation.
     Default: Regular instance creation.
     Restore: Creates an instance by restoring a set of backups to specific
     point in time. RestorePointInTime and SourceManagedInstanceId must be
     specified. Possible values include: 'Default', 'PointInTimeRestore'
    :type managed_instance_create_mode: str or
     ~azure.mgmt.sql.models.ManagedServerCreateMode
    :ivar fully_qualified_domain_name: The fully qualified domain name of the
     managed instance.
    :vartype fully_qualified_domain_name: str
    :param administrator_login: Administrator username for the managed
     instance. Can only be specified when the managed instance is being created
     (and is required for creation).
    :type administrator_login: str
    :param administrator_login_password: The administrator login password
     (required for managed instance creation).
    :type administrator_login_password: str
    :param subnet_id: Subnet resource ID for the managed instance.
    :type subnet_id: str
    :ivar state: The state of the managed instance.
    :vartype state: str
    :param license_type: The license type. Possible values are
     'LicenseIncluded' (regular price inclusive of a new SQL license) and
     'BasePrice' (discounted AHB price for bringing your own SQL licenses).
     Possible values include: 'LicenseIncluded', 'BasePrice'
    :type license_type: str or
     ~azure.mgmt.sql.models.ManagedInstanceLicenseType
    :param v_cores: The number of vCores. Allowed values: 8, 16, 24, 32, 40,
     64, 80.
    :type v_cores: int
    :param storage_size_in_gb: Storage size in GB. Minimum value: 32. Maximum
     value: 8192. Increments of 32 GB allowed only.
    :type storage_size_in_gb: int
    :param collation: Collation of the managed instance.
    :type collation: str
    :ivar dns_zone: The Dns Zone that the managed instance is in.
    :vartype dns_zone: str
    :param dns_zone_partner: The resource id of another managed instance whose
     DNS zone this managed instance will share after creation.
    :type dns_zone_partner: str
    :param public_data_endpoint_enabled: Whether or not the public data
     endpoint is enabled.
    :type public_data_endpoint_enabled: bool
    :param source_managed_instance_id: The resource identifier of the source
     managed instance associated with create operation of this instance.
    :type source_managed_instance_id: str
    :param restore_point_in_time: Specifies the point in time (ISO8601 format)
     of the source database that will be restored to create the new database.
    :type restore_point_in_time: datetime
    :param proxy_override: Connection type used for connecting to the
     instance. Possible values include: 'Proxy', 'Redirect', 'Default'
    :type proxy_override: str or
     ~azure.mgmt.sql.models.ManagedInstanceProxyOverride
    :param timezone_id: Id of the timezone. Allowed values are timezones
     supported by Windows.
     Windows keeps details on supported timezones, including the id, in
     registry under
     KEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time
     Zones.
     You can get those registry values via SQL Server by querying SELECT name
     AS timezone_id FROM sys.time_zone_info.
     List of Ids can also be obtained by executing
     [System.TimeZoneInfo]::GetSystemTimeZones() in PowerShell.
     An example of valid timezone id is "Pacific Standard Time" or "W. Europe
     Standard Time".
    :type timezone_id: str
    :param instance_pool_id: The Id of the instance pool this managed server
     belongs to.
    :type instance_pool_id: str
    :param maintenance_window_settings: Specifies maintenance window settings
     for a managed instance.
    :type maintenance_window_settings:
     ~azure.mgmt.sql.models.MaintenanceWindowSettings
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'fully_qualified_domain_name': {'readonly': True},
        'state': {'readonly': True},
        'dns_zone': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'identity': {'key': 'identity', 'type': 'ResourceIdentity'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'managed_instance_create_mode': {'key': 'properties.managedInstanceCreateMode', 'type': 'str'},
        'fully_qualified_domain_name': {'key': 'properties.fullyQualifiedDomainName', 'type': 'str'},
        'administrator_login': {'key': 'properties.administratorLogin', 'type': 'str'},
        'administrator_login_password': {'key': 'properties.administratorLoginPassword', 'type': 'str'},
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'license_type': {'key': 'properties.licenseType', 'type': 'str'},
        'v_cores': {'key': 'properties.vCores', 'type': 'int'},
        'storage_size_in_gb': {'key': 'properties.storageSizeInGB', 'type': 'int'},
        'collation': {'key': 'properties.collation', 'type': 'str'},
        'dns_zone': {'key': 'properties.dnsZone', 'type': 'str'},
        'dns_zone_partner': {'key': 'properties.dnsZonePartner', 'type': 'str'},
        'public_data_endpoint_enabled': {'key': 'properties.publicDataEndpointEnabled', 'type': 'bool'},
        'source_managed_instance_id': {'key': 'properties.sourceManagedInstanceId', 'type': 'str'},
        'restore_point_in_time': {'key': 'properties.restorePointInTime', 'type': 'iso-8601'},
        'proxy_override': {'key': 'properties.proxyOverride', 'type': 'str'},
        'timezone_id': {'key': 'properties.timezoneId', 'type': 'str'},
        'instance_pool_id': {'key': 'properties.instancePoolId', 'type': 'str'},
        'maintenance_window_settings': {'key': 'properties.maintenanceWindowSettings', 'type': 'MaintenanceWindowSettings'},
    }

    def __init__(self, *, location: str, tags=None, identity=None, sku=None, managed_instance_create_mode=None, administrator_login: str=None, administrator_login_password: str=None, subnet_id: str=None, license_type=None, v_cores: int=None, storage_size_in_gb: int=None, collation: str=None, dns_zone_partner: str=None, public_data_endpoint_enabled: bool=None, source_managed_instance_id: str=None, restore_point_in_time=None, proxy_override=None, timezone_id: str=None, instance_pool_id: str=None, maintenance_window_settings=None, **kwargs) -> None:
        super(ManagedInstance, self).__init__(location=location, tags=tags, **kwargs)
        self.identity = identity
        self.sku = sku
        self.managed_instance_create_mode = managed_instance_create_mode
        self.fully_qualified_domain_name = None
        self.administrator_login = administrator_login
        self.administrator_login_password = administrator_login_password
        self.subnet_id = subnet_id
        self.state = None
        self.license_type = license_type
        self.v_cores = v_cores
        self.storage_size_in_gb = storage_size_in_gb
        self.collation = collation
        self.dns_zone = None
        self.dns_zone_partner = dns_zone_partner
        self.public_data_endpoint_enabled = public_data_endpoint_enabled
        self.source_managed_instance_id = source_managed_instance_id
        self.restore_point_in_time = restore_point_in_time
        self.proxy_override = proxy_override
        self.timezone_id = timezone_id
        self.instance_pool_id = instance_pool_id
        self.maintenance_window_settings = maintenance_window_settings
