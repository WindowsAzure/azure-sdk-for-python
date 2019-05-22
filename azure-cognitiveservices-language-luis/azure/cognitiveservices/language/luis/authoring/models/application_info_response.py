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


class ApplicationInfoResponse(Model):
    """Response containing the Application Info.

    :param id: The ID (GUID) of the application.
    :type id: str
    :param name: The name of the application.
    :type name: str
    :param description: The description of the application.
    :type description: str
    :param culture: The culture of the application. For example, "en-us".
    :type culture: str
    :param usage_scenario: Defines the scenario for the new application.
     Optional. For example, IoT.
    :type usage_scenario: str
    :param domain: The domain for the new application. Optional. For example,
     Comics.
    :type domain: str
    :param versions_count: Amount of model versions within the application.
    :type versions_count: int
    :param created_date_time: The version's creation timestamp.
    :type created_date_time: str
    :param endpoints: The Runtime endpoint URL for this model version.
    :type endpoints: object
    :param endpoint_hits_count: Number of calls made to this endpoint.
    :type endpoint_hits_count: int
    :param active_version: The version ID currently marked as active.
    :type active_version: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'culture': {'key': 'culture', 'type': 'str'},
        'usage_scenario': {'key': 'usageScenario', 'type': 'str'},
        'domain': {'key': 'domain', 'type': 'str'},
        'versions_count': {'key': 'versionsCount', 'type': 'int'},
        'created_date_time': {'key': 'createdDateTime', 'type': 'str'},
        'endpoints': {'key': 'endpoints', 'type': 'object'},
        'endpoint_hits_count': {'key': 'endpointHitsCount', 'type': 'int'},
        'active_version': {'key': 'activeVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationInfoResponse, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.culture = kwargs.get('culture', None)
        self.usage_scenario = kwargs.get('usage_scenario', None)
        self.domain = kwargs.get('domain', None)
        self.versions_count = kwargs.get('versions_count', None)
        self.created_date_time = kwargs.get('created_date_time', None)
        self.endpoints = kwargs.get('endpoints', None)
        self.endpoint_hits_count = kwargs.get('endpoint_hits_count', None)
        self.active_version = kwargs.get('active_version', None)
