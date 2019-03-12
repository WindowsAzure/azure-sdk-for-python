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


class InformationProtectionPolicy(Resource):
    """Information protection policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :ivar last_modified_utc: Describes the last UTC time the policy was
     modified.
    :vartype last_modified_utc: datetime
    :param labels: Dictionary of sensitivity labels.
    :type labels: dict[str, ~azure.mgmt.security.models.SensitivityLabel]
    :param information_types: The sensitivity information types.
    :type information_types: dict[str,
     ~azure.mgmt.security.models.InformationType]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'last_modified_utc': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'last_modified_utc': {'key': 'properties.lastModifiedUtc', 'type': 'iso-8601'},
        'labels': {'key': 'properties.labels', 'type': '{SensitivityLabel}'},
        'information_types': {'key': 'properties.informationTypes', 'type': '{InformationType}'},
    }

    def __init__(self, *, labels=None, information_types=None, **kwargs) -> None:
        super(InformationProtectionPolicy, self).__init__(**kwargs)
        self.last_modified_utc = None
        self.labels = labels
        self.information_types = information_types
