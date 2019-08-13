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


class EntityKind1(Model):
    """Describes an entity with kind.

    :param kind: The kind of the entity. Possible values include: 'Account',
     'Host', 'File', 'AzureResource', 'CloudApplication', 'DnsResolution',
     'FileHash', 'Ip', 'Malware', 'Process', 'RegistryKey', 'RegistryValue',
     'SecurityGroup', 'Url', 'SecurityAlert', 'Bookmark'
    :type kind: str or ~azure.mgmt.securityinsight.models.EntityKind
    """

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
    }

    def __init__(self, *, kind=None, **kwargs) -> None:
        super(EntityKind1, self).__init__(**kwargs)
        self.kind = kind
