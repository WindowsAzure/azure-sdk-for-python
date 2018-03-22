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

from .sub_resource import SubResource


class PipelineResource(SubResource):
    """Pipeline resource type.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The resource identifier.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :ivar etag: Etag identifies change in the resource.
    :vartype etag: str
    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param description: The description of the pipeline.
    :type description: str
    :param activities: List of activities in pipeline.
    :type activities: list[~azure.mgmt.datafactory.models.Activity]
    :param parameters: List of parameters for pipeline.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param concurrency: The max number of concurrent runs for the pipeline.
    :type concurrency: int
    :param annotations: List of tags that can be used for describing the
     Pipeline.
    :type annotations: list[object]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'concurrency': {'minimum': 1},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'additional_properties': {'key': '', 'type': '{object}'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'activities': {'key': 'properties.activities', 'type': '[Activity]'},
        'parameters': {'key': 'properties.parameters', 'type': '{ParameterSpecification}'},
        'concurrency': {'key': 'properties.concurrency', 'type': 'int'},
        'annotations': {'key': 'properties.annotations', 'type': '[object]'},
    }

    def __init__(self, *, additional_properties=None, description: str=None, activities=None, parameters=None, concurrency: int=None, annotations=None, **kwargs) -> None:
        super(PipelineResource, self).__init__(, **kwargs)
        self.additional_properties = additional_properties
        self.description = description
        self.activities = activities
        self.parameters = parameters
        self.concurrency = concurrency
        self.annotations = annotations
