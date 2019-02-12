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

from .resource import Resource


class GalleryImage(Resource):
    """A gallery image.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The identifier of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: The location of the resource.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param author: The author of the gallery image.
    :type author: str
    :ivar created_date: The creation date of the gallery image.
    :vartype created_date: datetime
    :param description: The description of the gallery image.
    :type description: str
    :param image_reference: The image reference of the gallery image.
    :type image_reference:
     ~azure.mgmt.devtestlabs.models.GalleryImageReference
    :param icon: The icon of the gallery image.
    :type icon: str
    :param enabled: Indicates whether this gallery image is enabled.
    :type enabled: bool
    :param plan_id: The third party plan that applies to this image
    :type plan_id: str
    :param is_plan_authorized: Indicates if the plan has been authorized for
     programmatic deployment.
    :type is_plan_authorized: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_date': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'author': {'key': 'properties.author', 'type': 'str'},
        'created_date': {'key': 'properties.createdDate', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'image_reference': {'key': 'properties.imageReference', 'type': 'GalleryImageReference'},
        'icon': {'key': 'properties.icon', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'plan_id': {'key': 'properties.planId', 'type': 'str'},
        'is_plan_authorized': {'key': 'properties.isPlanAuthorized', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(GalleryImage, self).__init__(**kwargs)
        self.author = kwargs.get('author', None)
        self.created_date = None
        self.description = kwargs.get('description', None)
        self.image_reference = kwargs.get('image_reference', None)
        self.icon = kwargs.get('icon', None)
        self.enabled = kwargs.get('enabled', None)
        self.plan_id = kwargs.get('plan_id', None)
        self.is_plan_authorized = kwargs.get('is_plan_authorized', None)
