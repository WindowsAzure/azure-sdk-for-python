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

from .resource_with_etag_py3 import ResourceWithEtag


class Bookmark(ResourceWithEtag):
    """Represents a bookmark in Azure Security Insights.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param etag: Etag of the azure resource
    :type etag: str
    :param created: The time the bookmark was created
    :type created: datetime
    :param created_by: Describes a user that created the bookmark
    :type created_by: ~azure.mgmt.securityinsight.models.UserInfo
    :param display_name: Required. The display name of the bookmark
    :type display_name: str
    :param labels: List of labels relevant to this bookmark
    :type labels: list[str]
    :param notes: The notes of the bookmark
    :type notes: str
    :param query: Required. The query of the bookmark.
    :type query: str
    :param query_result: The query result of the bookmark.
    :type query_result: str
    :param updated: The last time the bookmark was updated
    :type updated: datetime
    :param updated_by: Describes a user that updated the bookmark
    :type updated_by: ~azure.mgmt.securityinsight.models.UserInfo
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'display_name': {'required': True},
        'query': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'created_by': {'key': 'properties.createdBy', 'type': 'UserInfo'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'labels': {'key': 'properties.labels', 'type': '[str]'},
        'notes': {'key': 'properties.notes', 'type': 'str'},
        'query': {'key': 'properties.query', 'type': 'str'},
        'query_result': {'key': 'properties.queryResult', 'type': 'str'},
        'updated': {'key': 'properties.updated', 'type': 'iso-8601'},
        'updated_by': {'key': 'properties.updatedBy', 'type': 'UserInfo'},
    }

    def __init__(self, *, display_name: str, query: str, etag: str=None, created=None, created_by=None, labels=None, notes: str=None, query_result: str=None, updated=None, updated_by=None, **kwargs) -> None:
        super(Bookmark, self).__init__(etag=etag, **kwargs)
        self.created = created
        self.created_by = created_by
        self.display_name = display_name
        self.labels = labels
        self.notes = notes
        self.query = query
        self.query_result = query_result
        self.updated = updated
        self.updated_by = updated_by
