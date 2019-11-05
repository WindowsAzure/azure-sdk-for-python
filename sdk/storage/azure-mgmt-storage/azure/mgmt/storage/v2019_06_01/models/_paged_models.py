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


class OperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.storage.v2019_06_01.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
class SkuInformationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SkuInformation <azure.mgmt.storage.v2019_06_01.models.SkuInformation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SkuInformation]'}
    }

    def __init__(self, *args, **kwargs):

        super(SkuInformationPaged, self).__init__(*args, **kwargs)
class StorageAccountPaged(Paged):
    """
    A paging container for iterating over a list of :class:`StorageAccount <azure.mgmt.storage.v2019_06_01.models.StorageAccount>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[StorageAccount]'}
    }

    def __init__(self, *args, **kwargs):

        super(StorageAccountPaged, self).__init__(*args, **kwargs)
class UsagePaged(Paged):
    """
    A paging container for iterating over a list of :class:`Usage <azure.mgmt.storage.v2019_06_01.models.Usage>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Usage]'}
    }

    def __init__(self, *args, **kwargs):

        super(UsagePaged, self).__init__(*args, **kwargs)
class BlobServicePropertiesPaged(Paged):
    """
    A paging container for iterating over a list of :class:`BlobServiceProperties <azure.mgmt.storage.v2019_06_01.models.BlobServiceProperties>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[BlobServiceProperties]'}
    }

    def __init__(self, *args, **kwargs):

        super(BlobServicePropertiesPaged, self).__init__(*args, **kwargs)
class ListContainerItemPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ListContainerItem <azure.mgmt.storage.v2019_06_01.models.ListContainerItem>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ListContainerItem]'}
    }

    def __init__(self, *args, **kwargs):

        super(ListContainerItemPaged, self).__init__(*args, **kwargs)
class FileShareItemPaged(Paged):
    """
    A paging container for iterating over a list of :class:`FileShareItem <azure.mgmt.storage.v2019_06_01.models.FileShareItem>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[FileShareItem]'}
    }

    def __init__(self, *args, **kwargs):

        super(FileShareItemPaged, self).__init__(*args, **kwargs)
