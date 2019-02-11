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

from .resource_py3 import Resource


class Action(Resource):
    """Action for alert rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param etag: Etag of the action.
    :type etag: str
    :param trigger_uri: The uri for the action to trigger.
    :type trigger_uri: str
    :ivar rule_id: The unique identifier of the rule.
    :vartype rule_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'rule_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'trigger_uri': {'key': 'properties.triggerUri', 'type': 'str'},
        'rule_id': {'key': 'properties.ruleId', 'type': 'str'},
    }

    def __init__(self, *, etag: str=None, trigger_uri: str=None, **kwargs) -> None:
        super(Action, self).__init__(**kwargs)
        self.etag = etag
        self.trigger_uri = trigger_uri
        self.rule_id = None
