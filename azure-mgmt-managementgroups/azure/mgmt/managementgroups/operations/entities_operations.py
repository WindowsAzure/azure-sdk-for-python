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

import uuid
from msrest.pipeline import ClientRawResponse

from .. import models


class EntitiesOperations(object):
    """EntitiesOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-01-01-preview. Constant value: "2018-03-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-03-01-preview"

        self.config = config

    def list(
            self, skiptoken=None, skip=None, top=None, select=None, search=None, filter=None, view=None, group_name=None, cache_control="no-cache", custom_headers=None, raw=False, **operation_config):
        """List all entities (Management Groups, Subscriptions, etc.) for the
        authenticated user.

        :param skiptoken: Page continuation token is only used if a previous
         operation returned a partial result. If a previous response contains a
         nextLink element, the value of the nextLink element will include a
         token parameter that specifies a starting point to use for subsequent
         calls.
        :type skiptoken: str
        :param skip: Number of entities to skip over when retrieving results.
         Passing this in will override $skipToken.
        :type skip: int
        :param top: Number of elements to return when retrieving results.
         Passing this in will override $skipToken.
        :type top: int
        :param select: This parameter specifies the fields to include in the
         response. Can include any combination of
         Name,DisplayName,Type,ParentDisplayNameChain,ParentChain, e.g.
         '$select=Name,DisplayName,Type,ParentDisplayNameChain,ParentNameChain'.
         When specified the $select parameter can override select in
         $skipToken.
        :type select: str
        :param search: The $search parameter is used in conjunction with the
         $filter parameter to return three different outputs depending on the
         parameter passed in. With $search=AllowedParents the API will return
         the entity info of all groups that the requested entity will be able
         to reparent to as determined by the user's permissions. With
         $search=AllowedChildren the API will return the entity info of all
         entities that can be added as children of the requested entity. With
         $search=ParentAndFirstLevelChildren the API will return the parent and
         first level of children that the user has either direct access to or
         indirect access via one of their descendants. Possible values include:
         'AllowedParents', 'AllowedChildren', 'ParentAndFirstLevelChildren',
         'ParentOnly', 'ChildrenOnly'
        :type search: str
        :param filter: The filter parameter allows you to filter on the name
         or display name fields. You can check for equality on the name field
         (e.g. name eq '{entityName}')  and you can check for substrings on
         either the name or display name fields(e.g. contains(name,
         '{substringToSearch}'), contains(displayName, '{substringToSearch')).
         Note that the '{entityName}' and '{substringToSearch}' fields are
         checked case insensitively.
        :type filter: str
        :param view: The view parameter allows clients to filter the type of
         data that is returned by the getEntities call. Possible values
         include: 'FullHierarchy', 'GroupsOnly', 'SubscriptionsOnly', 'Audit'
        :type view: str
        :param group_name: A filter which allows the get entities call to
         focus on a particular group (i.e. "$filter=name eq 'groupName'")
        :type group_name: str
        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of EntityInfo
        :rtype:
         ~azure.mgmt.managementgroups.models.EntityInfoPaged[~azure.mgmt.managementgroups.models.EntityInfo]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if select is not None:
                    query_parameters['$select'] = self._serialize.query("select", select, 'str')
                if search is not None:
                    query_parameters['$search'] = self._serialize.query("search", search, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if view is not None:
                    query_parameters['$view'] = self._serialize.query("view", view, 'str')
                if group_name is not None:
                    query_parameters['groupName'] = self._serialize.query("group_name", group_name, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if cache_control is not None:
                header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.post(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.EntityInfoPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.EntityInfoPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/providers/Microsoft.Management/getEntities'}
