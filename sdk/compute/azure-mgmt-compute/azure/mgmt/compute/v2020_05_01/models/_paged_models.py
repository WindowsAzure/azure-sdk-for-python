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


class DiskPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Disk <azure.mgmt.compute.v2020_05_01.models.Disk>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Disk]'}
    }

    def __init__(self, *args, **kwargs):

        super(DiskPaged, self).__init__(*args, **kwargs)
class SnapshotPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Snapshot <azure.mgmt.compute.v2020_05_01.models.Snapshot>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Snapshot]'}
    }

    def __init__(self, *args, **kwargs):

        super(SnapshotPaged, self).__init__(*args, **kwargs)
class DiskEncryptionSetPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DiskEncryptionSet <azure.mgmt.compute.v2020_05_01.models.DiskEncryptionSet>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DiskEncryptionSet]'}
    }

    def __init__(self, *args, **kwargs):

        super(DiskEncryptionSetPaged, self).__init__(*args, **kwargs)
class DiskAccessPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DiskAccess <azure.mgmt.compute.v2020_05_01.models.DiskAccess>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DiskAccess]'}
    }

    def __init__(self, *args, **kwargs):

        super(DiskAccessPaged, self).__init__(*args, **kwargs)
