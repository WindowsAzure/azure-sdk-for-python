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


class RegistryPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Registry <azure.mgmt.containerregistry.v2019_06_01_preview.models.Registry>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Registry]'}
    }

    def __init__(self, *args, **kwargs):

        super(RegistryPaged, self).__init__(*args, **kwargs)
class OperationDefinitionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`OperationDefinition <azure.mgmt.containerregistry.v2019_06_01_preview.models.OperationDefinition>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[OperationDefinition]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationDefinitionPaged, self).__init__(*args, **kwargs)
class ReplicationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Replication <azure.mgmt.containerregistry.v2019_06_01_preview.models.Replication>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Replication]'}
    }

    def __init__(self, *args, **kwargs):

        super(ReplicationPaged, self).__init__(*args, **kwargs)
class WebhookPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Webhook <azure.mgmt.containerregistry.v2019_06_01_preview.models.Webhook>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Webhook]'}
    }

    def __init__(self, *args, **kwargs):

        super(WebhookPaged, self).__init__(*args, **kwargs)
class EventPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Event <azure.mgmt.containerregistry.v2019_06_01_preview.models.Event>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Event]'}
    }

    def __init__(self, *args, **kwargs):

        super(EventPaged, self).__init__(*args, **kwargs)
class AgentPoolPaged(Paged):
    """
    A paging container for iterating over a list of :class:`AgentPool <azure.mgmt.containerregistry.v2019_06_01_preview.models.AgentPool>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[AgentPool]'}
    }

    def __init__(self, *args, **kwargs):

        super(AgentPoolPaged, self).__init__(*args, **kwargs)
class RunPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Run <azure.mgmt.containerregistry.v2019_06_01_preview.models.Run>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Run]'}
    }

    def __init__(self, *args, **kwargs):

        super(RunPaged, self).__init__(*args, **kwargs)
class TaskRunPaged(Paged):
    """
    A paging container for iterating over a list of :class:`TaskRun <azure.mgmt.containerregistry.v2019_06_01_preview.models.TaskRun>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[TaskRun]'}
    }

    def __init__(self, *args, **kwargs):

        super(TaskRunPaged, self).__init__(*args, **kwargs)
class TaskPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Task <azure.mgmt.containerregistry.v2019_06_01_preview.models.Task>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Task]'}
    }

    def __init__(self, *args, **kwargs):

        super(TaskPaged, self).__init__(*args, **kwargs)
class ScopeMapPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ScopeMap <azure.mgmt.containerregistry.v2019_06_01_preview.models.ScopeMap>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ScopeMap]'}
    }

    def __init__(self, *args, **kwargs):

        super(ScopeMapPaged, self).__init__(*args, **kwargs)
class TokenPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Token <azure.mgmt.containerregistry.v2019_06_01_preview.models.Token>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Token]'}
    }

    def __init__(self, *args, **kwargs):

        super(TokenPaged, self).__init__(*args, **kwargs)
