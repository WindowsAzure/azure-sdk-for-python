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

from .backup_entity import BackupEntity


class ServiceBackupEntity(BackupEntity):
    """Identifies the Service Fabric stateful service which is being backed up.

    All required parameters must be populated in order to send to Azure.

    :param entity_kind: Required. Constant filled by server.
    :type entity_kind: str
    :param service_name: The full name of the service with 'fabric:' URI
     scheme.
    :type service_name: str
    """

    _validation = {
        'entity_kind': {'required': True},
    }

    _attribute_map = {
        'entity_kind': {'key': 'EntityKind', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
    }

    def __init__(self, *, service_name: str=None, **kwargs) -> None:
        super(ServiceBackupEntity, self).__init__(, **kwargs)
        self.service_name = service_name
        self.entity_kind = 'Service'
