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

from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError
import uuid

from .. import models


class RecordSetsOperations(object):
    """RecordSetsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def update(
            self, resource_group_name, zone_name, relative_record_set_name, record_type, parameters, if_match=None, if_none_match=None, custom_headers=None, raw=False, **operation_config):
        """Updates a Recordset within a DNS zone.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param zone_name: The name of the zone without a terminating dot.
        :type zone_name: str
        :param relative_record_set_name: The name of the Recordset, relative
         to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record. Possible values include:
         'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'
        :type record_type: str or :class:`RecordType
         <azure.mgmt.dns.models.RecordType>`
        :param parameters: Parameters supplied to the Update operation.
        :type parameters: :class:`RecordSet <azure.mgmt.dns.models.RecordSet>`
        :param if_match: The etag of Zone.
        :type if_match: str
        :param if_none_match: Defines the If-None-Match condition. Set to '*'
         to force Create-If-Not-Exist. Other values will be ignored.
        :type if_none_match: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`RecordSet <azure.mgmt.dns.models.RecordSet>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/{recordType}/{relativeRecordSetName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'RecordType'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'RecordSet')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RecordSet', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_group_name, zone_name, relative_record_set_name, record_type, parameters, if_match=None, if_none_match=None, custom_headers=None, raw=False, **operation_config):
        """Creates or Updates a Recordset within a DNS zone.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param zone_name: The name of the zone without a terminating dot.
        :type zone_name: str
        :param relative_record_set_name: The name of the Recordset, relative
         to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record. Possible values include:
         'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'
        :type record_type: str or :class:`RecordType
         <azure.mgmt.dns.models.RecordType>`
        :param parameters: Parameters supplied to the CreateOrUpdate
         operation.
        :type parameters: :class:`RecordSet <azure.mgmt.dns.models.RecordSet>`
        :param if_match: The etag of Recordset.
        :type if_match: str
        :param if_none_match: Defines the If-None-Match condition. Set to '*'
         to force Create-If-Not-Exist. Other values will be ignored.
        :type if_none_match: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`RecordSet <azure.mgmt.dns.models.RecordSet>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/{recordType}/{relativeRecordSetName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'RecordType'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'RecordSet')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [201, 200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 201:
            deserialized = self._deserialize('RecordSet', response)
        if response.status_code == 200:
            deserialized = self._deserialize('RecordSet', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, resource_group_name, zone_name, relative_record_set_name, record_type, if_match=None, if_none_match=None, custom_headers=None, raw=False, **operation_config):
        """Removes a Recordset from a DNS zone.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param zone_name: The name of the zone without a terminating dot.
        :type zone_name: str
        :param relative_record_set_name: The name of the Recordset, relative
         to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record. Possible values include:
         'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'
        :type record_type: str or :class:`RecordType
         <azure.mgmt.dns.models.RecordType>`
        :param if_match: Defines the If-Match condition. The delete operation
         will be performed only if the ETag of the zone on the server matches
         this value.
        :type if_match: str
        :param if_none_match: Defines the If-None-Match condition. The delete
         operation will be performed only if the ETag of the zone on the
         server does not match this value.
        :type if_none_match: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: None
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/{recordType}/{relativeRecordSetName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'RecordType'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [204, 200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def get(
            self, resource_group_name, zone_name, relative_record_set_name, record_type, custom_headers=None, raw=False, **operation_config):
        """Gets a Recordset.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param zone_name: The name of the zone without a terminating dot.
        :type zone_name: str
        :param relative_record_set_name: The name of the Recordset, relative
         to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record. Possible values include:
         'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT'
        :type record_type: str or :class:`RecordType
         <azure.mgmt.dns.models.RecordType>`
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`RecordSet <azure.mgmt.dns.models.RecordSet>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/{recordType}/{relativeRecordSetName}'
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'RecordType'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RecordSet', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def list_by_type(
            self, resource_group_name, zone_name, record_type, top=None, custom_headers=None, raw=False, **operation_config):
        """Lists the Recordsets of a specified type in a DNS zone.

        :param resource_group_name: The name of the resource group that
         contains the zone.
        :type resource_group_name: str
        :param zone_name: The name of the zone from which to enumerate
         Recordsets.
        :type zone_name: str
        :param record_type: The type of record sets to enumerate. Possible
         values include: 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA',
         'SRV', 'TXT'
        :type record_type: str or :class:`RecordType
         <azure.mgmt.dns.models.RecordType>`
        :param top: Query parameters. If not specified returns the default
         number of recordsets.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`RecordSetPaged <azure.mgmt.dns.models.RecordSetPaged>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/{recordType}'
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
                    'recordType': self._serialize.url("record_type", record_type, 'RecordType'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.RecordSetPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.RecordSetPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def list_by_dns_zone(
            self, resource_group_name, zone_name, top=None, custom_headers=None, raw=False, **operation_config):
        """Lists all Recordsets in a DNS zone.

        :param resource_group_name: The name of the resource group that
         contains the zone.
        :type resource_group_name: str
        :param zone_name: The name of the zone from which to enumerate
         Recordsets.
        :type zone_name: str
        :param top: Query parameters. If not specified returns the default
         number of zones.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`RecordSetPaged <azure.mgmt.dns.models.RecordSetPaged>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnszones/{zoneName}/recordsets'
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("self.config.api_version", self.config.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.RecordSetPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.RecordSetPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
