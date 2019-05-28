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


class Policies(Model):
    """The policies for a container registry.

    :param quarantine_policy: The quarantine policy for a container registry.
    :type quarantine_policy:
     ~azure.mgmt.containerregistry.v2019_05_01.models.QuarantinePolicy
    :param trust_policy: The content trust policy for a container registry.
    :type trust_policy:
     ~azure.mgmt.containerregistry.v2019_05_01.models.TrustPolicy
    :param retention_policy: The retention policy for a container registry.
    :type retention_policy:
     ~azure.mgmt.containerregistry.v2019_05_01.models.RetentionPolicy
    """

    _attribute_map = {
        'quarantine_policy': {'key': 'quarantinePolicy', 'type': 'QuarantinePolicy'},
        'trust_policy': {'key': 'trustPolicy', 'type': 'TrustPolicy'},
        'retention_policy': {'key': 'retentionPolicy', 'type': 'RetentionPolicy'},
    }

    def __init__(self, *, quarantine_policy=None, trust_policy=None, retention_policy=None, **kwargs) -> None:
        super(Policies, self).__init__(**kwargs)
        self.quarantine_policy = quarantine_policy
        self.trust_policy = trust_policy
        self.retention_policy = retention_policy
