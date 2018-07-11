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


class BackupSuspensionInfo(Model):
    """Describes the backup suspension details.

    :param is_suspended: Indicates whether periodic backup is suspended at
     this level or not.
    :type is_suspended: bool
    :param suspension_inherited_from: Specifies the scope at which the backup
     suspension was applied. Possible values include: 'Invalid', 'Partition',
     'Service', 'Application'
    :type suspension_inherited_from: str or
     ~azure.servicefabric.models.BackupSuspensionScope
    """

    _attribute_map = {
        'is_suspended': {'key': 'IsSuspended', 'type': 'bool'},
        'suspension_inherited_from': {'key': 'SuspensionInheritedFrom', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(BackupSuspensionInfo, self).__init__(**kwargs)
        self.is_suspended = kwargs.get('is_suspended', None)
        self.suspension_inherited_from = kwargs.get('suspension_inherited_from', None)
