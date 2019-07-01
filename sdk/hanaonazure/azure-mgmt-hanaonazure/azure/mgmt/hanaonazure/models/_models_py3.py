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
from msrest.exceptions import HttpOperationError


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class Disk(Model):
    """Specifies the disk information fo the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: The disk name.
    :type name: str
    :param disk_size_gb: Specifies the size of an empty data disk in
     gigabytes.
    :type disk_size_gb: int
    :ivar lun: Specifies the logical unit number of the data disk. This value
     is used to identify data disks within the VM and therefore must be unique
     for each data disk attached to a VM.
    :vartype lun: int
    """

    _validation = {
        'lun': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'lun': {'key': 'lun', 'type': 'int'},
    }

    def __init__(self, *, name: str=None, disk_size_gb: int=None, **kwargs) -> None:
        super(Disk, self).__init__(**kwargs)
        self.name = name
        self.disk_size_gb = disk_size_gb
        self.lun = None


class Display(Model):
    """Detailed HANA operation information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: The localized friendly form of the resource provider name.
     This form is also expected to include the publisher/company responsible.
     Use Title Casing. Begin with "Microsoft" for 1st party services.
    :vartype provider: str
    :ivar resource: The localized friendly form of the resource type related
     to this action/operation. This form should match the public documentation
     for the resource provider. Use Title Casing. For examples, refer to the
     “name” section.
    :vartype resource: str
    :ivar operation: The localized friendly name for the operation as shown to
     the user. This name should be concise (to fit in drop downs), but clear
     (self-documenting). Use Title Casing and include the entity/resource to
     which it applies.
    :vartype operation: str
    :ivar description: The localized friendly description for the operation as
     shown to the user. This description should be thorough, yet concise. It
     will be used in tool-tips and detailed views.
    :vartype description: str
    :ivar origin: The intended executor of the operation; governs the display
     of the operation in the RBAC UX and the audit logs UX. Default value is
     'user,system'
    :vartype origin: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
        'description': {'readonly': True},
        'origin': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Display, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None
        self.description = None
        self.origin = None


class ErrorResponse(Model):
    """Describes the format of Error response.

    :param code: Error code
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class Resource(Model):
    """The resource model definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :ivar tags: Resource tags
    :vartype tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, location: str=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = None


class HanaInstance(Resource):
    """HANA instance info on Azure (ARM properties and HANA properties).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :ivar tags: Resource tags
    :vartype tags: dict[str, str]
    :param hardware_profile: Specifies the hardware settings for the HANA
     instance.
    :type hardware_profile: ~azure.mgmt.hanaonazure.models.HardwareProfile
    :param storage_profile: Specifies the storage settings for the HANA
     instance disks.
    :type storage_profile: ~azure.mgmt.hanaonazure.models.StorageProfile
    :param os_profile: Specifies the operating system settings for the HANA
     instance.
    :type os_profile: ~azure.mgmt.hanaonazure.models.OSProfile
    :param network_profile: Specifies the network settings for the HANA
     instance.
    :type network_profile: ~azure.mgmt.hanaonazure.models.NetworkProfile
    :ivar hana_instance_id: Specifies the HANA instance unique ID.
    :vartype hana_instance_id: str
    :ivar power_state: Resource power state. Possible values include:
     'starting', 'started', 'stopping', 'stopped', 'restarting', 'unknown'
    :vartype power_state: str or
     ~azure.mgmt.hanaonazure.models.HanaInstancePowerStateEnum
    :ivar proximity_placement_group: Resource proximity placement group
    :vartype proximity_placement_group: str
    :ivar hw_revision: Hardware revision of a HANA instance
    :vartype hw_revision: str
    :param partner_node_id: ARM ID of another HanaInstance that will share a
     network with this HanaInstance
    :type partner_node_id: str
    :ivar provisioning_state: State of provisioning of the HanaInstance.
     Possible values include: 'Accepted', 'Creating', 'Updating', 'Failed',
     'Succeeded', 'Deleting', 'Migrating'
    :vartype provisioning_state: str or
     ~azure.mgmt.hanaonazure.models.HanaProvisioningStatesEnum
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'hana_instance_id': {'readonly': True},
        'power_state': {'readonly': True},
        'proximity_placement_group': {'readonly': True},
        'hw_revision': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'hardware_profile': {'key': 'properties.hardwareProfile', 'type': 'HardwareProfile'},
        'storage_profile': {'key': 'properties.storageProfile', 'type': 'StorageProfile'},
        'os_profile': {'key': 'properties.osProfile', 'type': 'OSProfile'},
        'network_profile': {'key': 'properties.networkProfile', 'type': 'NetworkProfile'},
        'hana_instance_id': {'key': 'properties.hanaInstanceId', 'type': 'str'},
        'power_state': {'key': 'properties.powerState', 'type': 'str'},
        'proximity_placement_group': {'key': 'properties.proximityPlacementGroup', 'type': 'str'},
        'hw_revision': {'key': 'properties.hwRevision', 'type': 'str'},
        'partner_node_id': {'key': 'properties.partnerNodeId', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, hardware_profile=None, storage_profile=None, os_profile=None, network_profile=None, partner_node_id: str=None, **kwargs) -> None:
        super(HanaInstance, self).__init__(location=location, **kwargs)
        self.hardware_profile = hardware_profile
        self.storage_profile = storage_profile
        self.os_profile = os_profile
        self.network_profile = network_profile
        self.hana_instance_id = None
        self.power_state = None
        self.proximity_placement_group = None
        self.hw_revision = None
        self.partner_node_id = partner_node_id
        self.provisioning_state = None


class HardwareProfile(Model):
    """Specifies the hardware settings for the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar hardware_type: Name of the hardware type (vendor and/or their
     product name). Possible values include: 'Cisco_UCS', 'HPE'
    :vartype hardware_type: str or
     ~azure.mgmt.hanaonazure.models.HanaHardwareTypeNamesEnum
    :ivar hana_instance_size: Specifies the HANA instance SKU. Possible values
     include: 'S72m', 'S144m', 'S72', 'S144', 'S192', 'S192m', 'S192xm', 'S96',
     'S384', 'S384m', 'S384xm', 'S384xxm', 'S576m', 'S576xm', 'S768', 'S768m',
     'S768xm', 'S960m', 'S224o', 'S224m', 'S224om', 'S224oxm', 'S224oxxm'
    :vartype hana_instance_size: str or
     ~azure.mgmt.hanaonazure.models.HanaInstanceSizeNamesEnum
    """

    _validation = {
        'hardware_type': {'readonly': True},
        'hana_instance_size': {'readonly': True},
    }

    _attribute_map = {
        'hardware_type': {'key': 'hardwareType', 'type': 'str'},
        'hana_instance_size': {'key': 'hanaInstanceSize', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(HardwareProfile, self).__init__(**kwargs)
        self.hardware_type = None
        self.hana_instance_size = None


class IpAddress(Model):
    """Specifies the IP address of the network interface.

    :param ip_address: Specifies the IP address of the network interface.
    :type ip_address: str
    """

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
    }

    def __init__(self, *, ip_address: str=None, **kwargs) -> None:
        super(IpAddress, self).__init__(**kwargs)
        self.ip_address = ip_address


class MonitoringDetails(Model):
    """Details needed to monitor a Hana Instance.

    :param hana_subnet: ARM ID of an Azure Subnet with access to the HANA
     instance.
    :type hana_subnet: str
    :param hana_hostname: Hostname of the HANA Instance blade.
    :type hana_hostname: str
    :param hana_db_name: Name of the database itself.
    :type hana_db_name: str
    :param hana_db_sql_port: The port number of the tenant DB. Used to connect
     to the DB.
    :type hana_db_sql_port: int
    :param hana_db_username: Username for the HANA database to login to for
     monitoring
    :type hana_db_username: str
    :param hana_db_password: Password for the HANA database to login for
     monitoring
    :type hana_db_password: str
    """

    _attribute_map = {
        'hana_subnet': {'key': 'hanaSubnet', 'type': 'str'},
        'hana_hostname': {'key': 'hanaHostname', 'type': 'str'},
        'hana_db_name': {'key': 'hanaDbName', 'type': 'str'},
        'hana_db_sql_port': {'key': 'hanaDbSqlPort', 'type': 'int'},
        'hana_db_username': {'key': 'hanaDbUsername', 'type': 'str'},
        'hana_db_password': {'key': 'hanaDbPassword', 'type': 'str'},
    }

    def __init__(self, *, hana_subnet: str=None, hana_hostname: str=None, hana_db_name: str=None, hana_db_sql_port: int=None, hana_db_username: str=None, hana_db_password: str=None, **kwargs) -> None:
        super(MonitoringDetails, self).__init__(**kwargs)
        self.hana_subnet = hana_subnet
        self.hana_hostname = hana_hostname
        self.hana_db_name = hana_db_name
        self.hana_db_sql_port = hana_db_sql_port
        self.hana_db_username = hana_db_username
        self.hana_db_password = hana_db_password


class NetworkProfile(Model):
    """Specifies the network settings for the HANA instance disks.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param network_interfaces: Specifies the network interfaces for the HANA
     instance.
    :type network_interfaces: list[~azure.mgmt.hanaonazure.models.IpAddress]
    :ivar circuit_id: Specifies the circuit id for connecting to express
     route.
    :vartype circuit_id: str
    """

    _validation = {
        'circuit_id': {'readonly': True},
    }

    _attribute_map = {
        'network_interfaces': {'key': 'networkInterfaces', 'type': '[IpAddress]'},
        'circuit_id': {'key': 'circuitId', 'type': 'str'},
    }

    def __init__(self, *, network_interfaces=None, **kwargs) -> None:
        super(NetworkProfile, self).__init__(**kwargs)
        self.network_interfaces = network_interfaces
        self.circuit_id = None


class Operation(Model):
    """HANA operation information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The name of the operation being performed on this particular
     object. This name should match the action name that appears in RBAC / the
     event service.
    :vartype name: str
    :param display: Displayed HANA operation information
    :type display: ~azure.mgmt.hanaonazure.models.Display
    """

    _validation = {
        'name': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'Display'},
    }

    def __init__(self, *, display=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = display


class OSProfile(Model):
    """Specifies the operating system settings for the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param computer_name: Specifies the host OS name of the HANA instance.
    :type computer_name: str
    :ivar os_type: This property allows you to specify the type of the OS.
    :vartype os_type: str
    :ivar version: Specifies version of operating system.
    :vartype version: str
    :param ssh_public_key: Specifies the SSH public key used to access the
     operating system.
    :type ssh_public_key: str
    """

    _validation = {
        'os_type': {'readonly': True},
        'version': {'readonly': True},
    }

    _attribute_map = {
        'computer_name': {'key': 'computerName', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'ssh_public_key': {'key': 'sshPublicKey', 'type': 'str'},
    }

    def __init__(self, *, computer_name: str=None, ssh_public_key: str=None, **kwargs) -> None:
        super(OSProfile, self).__init__(**kwargs)
        self.computer_name = computer_name
        self.os_type = None
        self.version = None
        self.ssh_public_key = ssh_public_key


class SapMonitor(Resource):
    """SAP monitor info on Azure (ARM properties and SAP monitor properties).

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :ivar tags: Resource tags
    :vartype tags: dict[str, str]
    :param hana_subnet: Specifies the SAP monitor unique ID.
    :type hana_subnet: str
    :param hana_hostname: Hostname of the HANA instance.
    :type hana_hostname: str
    :param hana_db_name: Database name of the HANA instance.
    :type hana_db_name: str
    :param hana_db_sql_port: Database port of the HANA instance.
    :type hana_db_sql_port: int
    :param hana_db_username: Database username of the HANA instance.
    :type hana_db_username: str
    :param hana_db_password: Database password of the HANA instance.
    :type hana_db_password: str
    :ivar provisioning_state: State of provisioning of the HanaInstance.
     Possible values include: 'Accepted', 'Creating', 'Updating', 'Failed',
     'Succeeded', 'Deleting', 'Migrating'
    :vartype provisioning_state: str or
     ~azure.mgmt.hanaonazure.models.HanaProvisioningStatesEnum
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'hana_subnet': {'key': 'properties.hanaSubnet', 'type': 'str'},
        'hana_hostname': {'key': 'properties.hanaHostname', 'type': 'str'},
        'hana_db_name': {'key': 'properties.hanaDbName', 'type': 'str'},
        'hana_db_sql_port': {'key': 'properties.hanaDbSqlPort', 'type': 'int'},
        'hana_db_username': {'key': 'properties.hanaDbUsername', 'type': 'str'},
        'hana_db_password': {'key': 'properties.hanaDbPassword', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, hana_subnet: str=None, hana_hostname: str=None, hana_db_name: str=None, hana_db_sql_port: int=None, hana_db_username: str=None, hana_db_password: str=None, **kwargs) -> None:
        super(SapMonitor, self).__init__(location=location, **kwargs)
        self.hana_subnet = hana_subnet
        self.hana_hostname = hana_hostname
        self.hana_db_name = hana_db_name
        self.hana_db_sql_port = hana_db_sql_port
        self.hana_db_username = hana_db_username
        self.hana_db_password = hana_db_password
        self.provisioning_state = None


class StorageProfile(Model):
    """Specifies the storage settings for the HANA instance disks.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar nfs_ip_address: IP Address to connect to storage.
    :vartype nfs_ip_address: str
    :param os_disks: Specifies information about the operating system disk
     used by the hana instance.
    :type os_disks: list[~azure.mgmt.hanaonazure.models.Disk]
    """

    _validation = {
        'nfs_ip_address': {'readonly': True},
    }

    _attribute_map = {
        'nfs_ip_address': {'key': 'nfsIpAddress', 'type': 'str'},
        'os_disks': {'key': 'osDisks', 'type': '[Disk]'},
    }

    def __init__(self, *, os_disks=None, **kwargs) -> None:
        super(StorageProfile, self).__init__(**kwargs)
        self.nfs_ip_address = None
        self.os_disks = os_disks


class Tags(Model):
    """Tags field of the HANA instance.

    :param tags: Tags field of the HANA instance.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, **kwargs) -> None:
        super(Tags, self).__init__(**kwargs)
        self.tags = tags
