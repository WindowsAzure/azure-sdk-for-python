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

from .azure_vm_workload_item_py3 import AzureVmWorkloadItem


class AzureVmWorkloadSAPHanaSystemWorkloadItem(AzureVmWorkloadItem):
    """Azure VM workload-specific workload item representing SAP HANA System.

    All required parameters must be populated in order to send to Azure.

    :param backup_management_type: Type of backup management to backup an
     item.
    :type backup_management_type: str
    :param workload_type: Type of workload for the backup management
    :type workload_type: str
    :param friendly_name: Friendly name of the backup item.
    :type friendly_name: str
    :param protection_state: State of the back up item. Possible values
     include: 'Invalid', 'NotProtected', 'Protecting', 'Protected',
     'ProtectionFailed'
    :type protection_state: str or
     ~azure.mgmt.recoveryservicesbackup.models.ProtectionStatus
    :param workload_item_type: Required. Constant filled by server.
    :type workload_item_type: str
    :param parent_name: Name for instance or AG
    :type parent_name: str
    :param server_name: Host/Cluster Name for instance or AG
    :type server_name: str
    :param is_auto_protectable: Indicates if workload item is auto-protectable
    :type is_auto_protectable: bool
    :param subinquireditemcount: For instance or AG, indicates number of DB's
     present
    :type subinquireditemcount: int
    :param sub_workload_item_count: For instance or AG, indicates number of
     DB's to be protected
    :type sub_workload_item_count: int
    """

    _validation = {
        'workload_item_type': {'required': True},
    }

    _attribute_map = {
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'workload_type': {'key': 'workloadType', 'type': 'str'},
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'protection_state': {'key': 'protectionState', 'type': 'str'},
        'workload_item_type': {'key': 'workloadItemType', 'type': 'str'},
        'parent_name': {'key': 'parentName', 'type': 'str'},
        'server_name': {'key': 'serverName', 'type': 'str'},
        'is_auto_protectable': {'key': 'isAutoProtectable', 'type': 'bool'},
        'subinquireditemcount': {'key': 'subinquireditemcount', 'type': 'int'},
        'sub_workload_item_count': {'key': 'subWorkloadItemCount', 'type': 'int'},
    }

    def __init__(self, *, backup_management_type: str=None, workload_type: str=None, friendly_name: str=None, protection_state=None, parent_name: str=None, server_name: str=None, is_auto_protectable: bool=None, subinquireditemcount: int=None, sub_workload_item_count: int=None, **kwargs) -> None:
        super(AzureVmWorkloadSAPHanaSystemWorkloadItem, self).__init__(backup_management_type=backup_management_type, workload_type=workload_type, friendly_name=friendly_name, protection_state=protection_state, parent_name=parent_name, server_name=server_name, is_auto_protectable=is_auto_protectable, subinquireditemcount=subinquireditemcount, sub_workload_item_count=sub_workload_item_count, **kwargs)
        self.workload_item_type = 'SAPHanaSystem'
