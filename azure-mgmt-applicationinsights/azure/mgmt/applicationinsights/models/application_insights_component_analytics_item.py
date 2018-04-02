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


class ApplicationInsightsComponentAnalyticsItem(Model):
    """Properties that define an Analytics item that is associated to an
    Application Insights component.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Internally assigned unique id of the item definition.
    :type id: str
    :param name: The user-defined name of the item.
    :type name: str
    :param content: The content of this item
    :type content: str
    :ivar version: This instance's version of the data model. This can change
     as new features are added.
    :vartype version: str
    :param scope: Enum indicating if this item definition is owned by a
     specific user or is shared between all users with access to the
     Application Insights component. Possible values include: 'shared', 'user'
    :type scope: str or ~azure.mgmt.applicationinsights.models.ItemScope
    :param type: Enum indicating the type of the Analytics item. Possible
     values include: 'query', 'function', 'folder', 'recent'
    :type type: str or ~azure.mgmt.applicationinsights.models.ItemType
    :ivar time_created: Date and time in UTC when this item was created.
    :vartype time_created: str
    :ivar time_modified: Date and time in UTC of the last modification that
     was made to this item.
    :vartype time_modified: str
    :param properties:
    :type properties:
     ~azure.mgmt.applicationinsights.models.ApplicationInsightsComponentAnalyticsItemProperties
    """

    _validation = {
        'version': {'readonly': True},
        'time_created': {'readonly': True},
        'time_modified': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
        'name': {'key': 'Name', 'type': 'str'},
        'content': {'key': 'Content', 'type': 'str'},
        'version': {'key': 'Version', 'type': 'str'},
        'scope': {'key': 'Scope', 'type': 'str'},
        'type': {'key': 'Type', 'type': 'str'},
        'time_created': {'key': 'TimeCreated', 'type': 'str'},
        'time_modified': {'key': 'TimeModified', 'type': 'str'},
        'properties': {'key': 'Properties', 'type': 'ApplicationInsightsComponentAnalyticsItemProperties'},
    }

    def __init__(self, id=None, name=None, content=None, scope=None, type=None, properties=None):
        super(ApplicationInsightsComponentAnalyticsItem, self).__init__()
        self.id = id
        self.name = name
        self.content = content
        self.version = None
        self.scope = scope
        self.type = type
        self.time_created = None
        self.time_modified = None
        self.properties = properties
