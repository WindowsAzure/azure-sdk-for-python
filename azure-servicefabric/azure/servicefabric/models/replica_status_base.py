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


class ReplicaStatusBase(Model):
    """Information about the replica.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: KeyValueStoreReplicaStatus

    :param kind: Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'KeyValueStore': 'KeyValueStoreReplicaStatus'}
    }

    def __init__(self):
        super(ReplicaStatusBase, self).__init__()
        self.kind = None
