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
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.resource.resources.v2018_05_01.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
class DeploymentExtendedPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DeploymentExtended <azure.mgmt.resource.resources.v2018_05_01.models.DeploymentExtended>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DeploymentExtended]'}
    }

    def __init__(self, *args, **kwargs):

        super(DeploymentExtendedPaged, self).__init__(*args, **kwargs)
class ProviderPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Provider <azure.mgmt.resource.resources.v2018_05_01.models.Provider>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Provider]'}
    }

    def __init__(self, *args, **kwargs):

        super(ProviderPaged, self).__init__(*args, **kwargs)
class GenericResourceExpandedPaged(Paged):
    """
    A paging container for iterating over a list of :class:`GenericResourceExpanded <azure.mgmt.resource.resources.v2018_05_01.models.GenericResourceExpanded>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[GenericResourceExpanded]'}
    }

    def __init__(self, *args, **kwargs):

        super(GenericResourceExpandedPaged, self).__init__(*args, **kwargs)
class ResourceGroupPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ResourceGroup <azure.mgmt.resource.resources.v2018_05_01.models.ResourceGroup>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ResourceGroup]'}
    }

    def __init__(self, *args, **kwargs):

        super(ResourceGroupPaged, self).__init__(*args, **kwargs)
class TagDetailsPaged(Paged):
    """
    A paging container for iterating over a list of :class:`TagDetails <azure.mgmt.resource.resources.v2018_05_01.models.TagDetails>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[TagDetails]'}
    }

    def __init__(self, *args, **kwargs):

        super(TagDetailsPaged, self).__init__(*args, **kwargs)
class DeploymentOperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DeploymentOperation <azure.mgmt.resource.resources.v2018_05_01.models.DeploymentOperation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DeploymentOperation]'}
    }

    def __init__(self, *args, **kwargs):

        super(DeploymentOperationPaged, self).__init__(*args, **kwargs)
