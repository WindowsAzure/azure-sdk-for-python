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


class SnapshotRecoveryRequest(ProxyOnlyResource):
    """Details about app recovery operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param snapshot_time: Point in time in which the app recovery should be
     attempted, formatted as a DateTime string.
    :type snapshot_time: str
    :param recovery_target: Specifies the web app that snapshot contents will
     be written to.
    :type recovery_target: ~azure.mgmt.web.models.SnapshotRecoveryTarget
    :param overwrite: Required. If <code>true</code> the recovery operation
     can overwrite source app; otherwise, <code>false</code>.
    :type overwrite: bool
    :param recover_configuration: If true, site configuration, in addition to
     content, will be reverted.
    :type recover_configuration: bool
    :param ignore_conflicting_host_names: If true, custom hostname conflicts
     will be ignored when recovering to a target web app.
     This setting is only necessary when RecoverConfiguration is enabled.
    :type ignore_conflicting_host_names: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'overwrite': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'snapshot_time': {'key': 'properties.snapshotTime', 'type': 'str'},
        'recovery_target': {'key': 'properties.recoveryTarget', 'type': 'SnapshotRecoveryTarget'},
        'overwrite': {'key': 'properties.overwrite', 'type': 'bool'},
        'recover_configuration': {'key': 'properties.recoverConfiguration', 'type': 'bool'},
        'ignore_conflicting_host_names': {'key': 'properties.ignoreConflictingHostNames', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(SnapshotRecoveryRequest, self).__init__(**kwargs)
        self.snapshot_time = kwargs.get('snapshot_time', None)
        self.recovery_target = kwargs.get('recovery_target', None)
        self.overwrite = kwargs.get('overwrite', None)
        self.recover_configuration = kwargs.get('recover_configuration', None)
        self.ignore_conflicting_host_names = kwargs.get('ignore_conflicting_host_names', None)
