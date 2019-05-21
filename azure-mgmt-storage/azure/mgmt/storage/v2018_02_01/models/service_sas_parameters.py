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


class ServiceSasParameters(Model):
    """The parameters to list service SAS credentials of a specific resource.

    All required parameters must be populated in order to send to Azure.

    :param canonicalized_resource: Required. The canonical path to the signed
     resource.
    :type canonicalized_resource: str
    :param resource: The signed services accessible with the service SAS.
     Possible values include: Blob (b), Container (c), File (f), Share (s).
     Possible values include: 'b', 'c', 'f', 's'
    :type resource: str or
     ~azure.mgmt.storage.v2018_02_01.models.SignedResource
    :param permissions: The signed permissions for the service SAS. Possible
     values include: Read (r), Write (w), Delete (d), List (l), Add (a), Create
     (c), Update (u) and Process (p). Possible values include: 'r', 'd', 'w',
     'l', 'a', 'c', 'u', 'p'
    :type permissions: str or
     ~azure.mgmt.storage.v2018_02_01.models.Permissions
    :param ip_address_or_range: An IP address or a range of IP addresses from
     which to accept requests.
    :type ip_address_or_range: str
    :param protocols: The protocol permitted for a request made with the
     account SAS. Possible values include: 'https,http', 'https'
    :type protocols: str or
     ~azure.mgmt.storage.v2018_02_01.models.HttpProtocol
    :param shared_access_start_time: The time at which the SAS becomes valid.
    :type shared_access_start_time: datetime
    :param shared_access_expiry_time: The time at which the shared access
     signature becomes invalid.
    :type shared_access_expiry_time: datetime
    :param identifier: A unique value up to 64 characters in length that
     correlates to an access policy specified for the container, queue, or
     table.
    :type identifier: str
    :param partition_key_start: The start of partition key.
    :type partition_key_start: str
    :param partition_key_end: The end of partition key.
    :type partition_key_end: str
    :param row_key_start: The start of row key.
    :type row_key_start: str
    :param row_key_end: The end of row key.
    :type row_key_end: str
    :param key_to_sign: The key to sign the account SAS token with.
    :type key_to_sign: str
    :param cache_control: The response header override for cache control.
    :type cache_control: str
    :param content_disposition: The response header override for content
     disposition.
    :type content_disposition: str
    :param content_encoding: The response header override for content
     encoding.
    :type content_encoding: str
    :param content_language: The response header override for content
     language.
    :type content_language: str
    :param content_type: The response header override for content type.
    :type content_type: str
    """

    _validation = {
        'canonicalized_resource': {'required': True},
        'identifier': {'max_length': 64},
    }

    _attribute_map = {
        'canonicalized_resource': {'key': 'canonicalizedResource', 'type': 'str'},
        'resource': {'key': 'signedResource', 'type': 'str'},
        'permissions': {'key': 'signedPermission', 'type': 'str'},
        'ip_address_or_range': {'key': 'signedIp', 'type': 'str'},
        'protocols': {'key': 'signedProtocol', 'type': 'HttpProtocol'},
        'shared_access_start_time': {'key': 'signedStart', 'type': 'iso-8601'},
        'shared_access_expiry_time': {'key': 'signedExpiry', 'type': 'iso-8601'},
        'identifier': {'key': 'signedIdentifier', 'type': 'str'},
        'partition_key_start': {'key': 'startPk', 'type': 'str'},
        'partition_key_end': {'key': 'endPk', 'type': 'str'},
        'row_key_start': {'key': 'startRk', 'type': 'str'},
        'row_key_end': {'key': 'endRk', 'type': 'str'},
        'key_to_sign': {'key': 'keyToSign', 'type': 'str'},
        'cache_control': {'key': 'rscc', 'type': 'str'},
        'content_disposition': {'key': 'rscd', 'type': 'str'},
        'content_encoding': {'key': 'rsce', 'type': 'str'},
        'content_language': {'key': 'rscl', 'type': 'str'},
        'content_type': {'key': 'rsct', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServiceSasParameters, self).__init__(**kwargs)
        self.canonicalized_resource = kwargs.get('canonicalized_resource', None)
        self.resource = kwargs.get('resource', None)
        self.permissions = kwargs.get('permissions', None)
        self.ip_address_or_range = kwargs.get('ip_address_or_range', None)
        self.protocols = kwargs.get('protocols', None)
        self.shared_access_start_time = kwargs.get('shared_access_start_time', None)
        self.shared_access_expiry_time = kwargs.get('shared_access_expiry_time', None)
        self.identifier = kwargs.get('identifier', None)
        self.partition_key_start = kwargs.get('partition_key_start', None)
        self.partition_key_end = kwargs.get('partition_key_end', None)
        self.row_key_start = kwargs.get('row_key_start', None)
        self.row_key_end = kwargs.get('row_key_end', None)
        self.key_to_sign = kwargs.get('key_to_sign', None)
        self.cache_control = kwargs.get('cache_control', None)
        self.content_disposition = kwargs.get('content_disposition', None)
        self.content_encoding = kwargs.get('content_encoding', None)
        self.content_language = kwargs.get('content_language', None)
        self.content_type = kwargs.get('content_type', None)
