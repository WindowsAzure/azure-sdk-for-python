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


class Workbook(Resource):
    """An Application Insights workbook definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param kind: The kind of workbook. Choices are user and shared. Possible
     values include: 'user', 'shared'
    :type kind: str or ~azure.mgmt.applicationinsights.models.SharedTypeKind
    :param workbook_name: Required. The user-defined name of the workbook.
    :type workbook_name: str
    :param serialized_data: Required. Configuration of this particular
     workbook. Configuration data is a string containing valid JSON
    :type serialized_data: str
    :param version: This instance's version of the data model. This can change
     as new features are added that can be marked workbook.
    :type version: str
    :param workbook_id: Required. Internally assigned unique id of the
     workbook definition.
    :type workbook_id: str
    :param shared_type_kind: Required. Enum indicating if this workbook
     definition is owned by a specific user or is shared between all users with
     access to the Application Insights component. Possible values include:
     'user', 'shared'. Default value: "shared" .
    :type shared_type_kind: str or
     ~azure.mgmt.applicationinsights.models.SharedTypeKind
    :ivar time_modified: Date and time in UTC of the last modification that
     was made to this workbook definition.
    :vartype time_modified: str
    :param category: Required. Workbook category, as defined by the user at
     creation time.
    :type category: str
    :param workbook_tags: A list of 0 or more tags that are associated with
     this workbook definition
    :type workbook_tags: list[str]
    :param user_id: Required. Unique user id of the specific user that owns
     this workbook.
    :type user_id: str
    :param source_resource_id: Optional resourceId for a source resource.
    :type source_resource_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'workbook_name': {'required': True},
        'serialized_data': {'required': True},
        'workbook_id': {'required': True},
        'shared_type_kind': {'required': True},
        'time_modified': {'readonly': True},
        'category': {'required': True},
        'user_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'kind': {'key': 'kind', 'type': 'str'},
        'workbook_name': {'key': 'properties.name', 'type': 'str'},
        'serialized_data': {'key': 'properties.serializedData', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'workbook_id': {'key': 'properties.workbookId', 'type': 'str'},
        'shared_type_kind': {'key': 'properties.kind', 'type': 'str'},
        'time_modified': {'key': 'properties.timeModified', 'type': 'str'},
        'category': {'key': 'properties.category', 'type': 'str'},
        'workbook_tags': {'key': 'properties.tags', 'type': '[str]'},
        'user_id': {'key': 'properties.userId', 'type': 'str'},
        'source_resource_id': {'key': 'properties.sourceResourceId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Workbook, self).__init__(**kwargs)
        self.kind = kwargs.get('kind', None)
        self.workbook_name = kwargs.get('workbook_name', None)
        self.serialized_data = kwargs.get('serialized_data', None)
        self.version = kwargs.get('version', None)
        self.workbook_id = kwargs.get('workbook_id', None)
        self.shared_type_kind = kwargs.get('shared_type_kind', "shared")
        self.time_modified = None
        self.category = kwargs.get('category', None)
        self.workbook_tags = kwargs.get('workbook_tags', None)
        self.user_id = kwargs.get('user_id', None)
        self.source_resource_id = kwargs.get('source_resource_id', None)
