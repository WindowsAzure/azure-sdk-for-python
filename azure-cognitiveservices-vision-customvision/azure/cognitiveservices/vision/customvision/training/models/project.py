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


class Project(Model):
    """Represents a project.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Gets the project id
    :vartype id: str
    :param name: Gets or sets the name of the project
    :type name: str
    :param description: Gets or sets the description of the project
    :type description: str
    :param settings: Gets or sets the project settings
    :type settings:
     ~azure.cognitiveservices.vision.customvision.training.models.ProjectSettings
    :ivar created: Gets the date this project was created
    :vartype created: datetime
    :ivar last_modified: Gets the date this project was last modifed
    :vartype last_modified: datetime
    :ivar thumbnail_uri: Gets the thumbnail url representing the project
    :vartype thumbnail_uri: str
    """

    _validation = {
        'id': {'readonly': True},
        'created': {'readonly': True},
        'last_modified': {'readonly': True},
        'thumbnail_uri': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'settings': {'key': 'settings', 'type': 'ProjectSettings'},
        'created': {'key': 'created', 'type': 'iso-8601'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'thumbnail_uri': {'key': 'thumbnailUri', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Project, self).__init__(**kwargs)
        self.id = None
        self.name = kwargs.get('name', None)
        self.description = kwargs.get('description', None)
        self.settings = kwargs.get('settings', None)
        self.created = None
        self.last_modified = None
        self.thumbnail_uri = None
