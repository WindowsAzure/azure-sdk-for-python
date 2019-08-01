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

from msrest.paging import Paged


class ReplicationUsagePaged(Paged):
    """
    A paging container for iterating over a list of :class:`ReplicationUsage <azure.mgmt.recoveryservices.models.ReplicationUsage>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ReplicationUsage]'}
    }

    def __init__(self, *args, **kwargs):

        super(ReplicationUsagePaged, self).__init__(*args, **kwargs)
class VaultPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Vault <azure.mgmt.recoveryservices.models.Vault>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Vault]'}
    }

    def __init__(self, *args, **kwargs):

        super(VaultPaged, self).__init__(*args, **kwargs)
class ClientDiscoveryValueForSingleApiPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ClientDiscoveryValueForSingleApi <azure.mgmt.recoveryservices.models.ClientDiscoveryValueForSingleApi>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ClientDiscoveryValueForSingleApi]'}
    }

    def __init__(self, *args, **kwargs):

        super(ClientDiscoveryValueForSingleApiPaged, self).__init__(*args, **kwargs)
class VaultUsagePaged(Paged):
    """
    A paging container for iterating over a list of :class:`VaultUsage <azure.mgmt.recoveryservices.models.VaultUsage>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VaultUsage]'}
    }

    def __init__(self, *args, **kwargs):

        super(VaultUsagePaged, self).__init__(*args, **kwargs)
