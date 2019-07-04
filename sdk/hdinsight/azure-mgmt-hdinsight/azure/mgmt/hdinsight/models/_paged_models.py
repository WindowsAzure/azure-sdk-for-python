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


class ClusterPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Cluster <azure.mgmt.hdinsight.models.Cluster>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Cluster]'}
    }

    def __init__(self, *args, **kwargs):

        super(ClusterPaged, self).__init__(*args, **kwargs)
class ApplicationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Application <azure.mgmt.hdinsight.models.Application>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Application]'}
    }

    def __init__(self, *args, **kwargs):

        super(ApplicationPaged, self).__init__(*args, **kwargs)
class RuntimeScriptActionDetailPaged(Paged):
    """
    A paging container for iterating over a list of :class:`RuntimeScriptActionDetail <azure.mgmt.hdinsight.models.RuntimeScriptActionDetail>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[RuntimeScriptActionDetail]'}
    }

    def __init__(self, *args, **kwargs):

        super(RuntimeScriptActionDetailPaged, self).__init__(*args, **kwargs)
class OperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.hdinsight.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
