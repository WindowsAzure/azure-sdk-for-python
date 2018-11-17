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


class EndpointUpdateParameters(Model):
    """Properties required to create or update an endpoint.

    :param tags: Endpoint tags.
    :type tags: dict[str, str]
    :param origin_host_header: The host header value sent to the origin with
     each request. If you leave this blank, the request hostname determines
     this value. Azure CDN origins, such as Web Apps, Blob Storage, and Cloud
     Services require this host header value to match the origin hostname by
     default.
    :type origin_host_header: str
    :param origin_path: A directory path on the origin that CDN can use to
     retreive content from, e.g. contoso.cloudapp.net/originpath.
    :type origin_path: str
    :param content_types_to_compress: List of content types on which
     compression applies. The value should be a valid MIME type.
    :type content_types_to_compress: list[str]
    :param is_compression_enabled: Indicates whether content compression is
     enabled on CDN. Default value is false. If compression is enabled, content
     will be served as compressed if user requests for a compressed version.
     Content won't be compressed on CDN when requested content is smaller than
     1 byte or larger than 1 MB.
    :type is_compression_enabled: bool
    :param is_http_allowed: Indicates whether HTTP traffic is allowed on the
     endpoint. Default value is true. At least one protocol (HTTP or HTTPS)
     must be allowed.
    :type is_http_allowed: bool
    :param is_https_allowed: Indicates whether HTTPS traffic is allowed on the
     endpoint. Default value is true. At least one protocol (HTTP or HTTPS)
     must be allowed.
    :type is_https_allowed: bool
    :param query_string_caching_behavior: Defines how CDN caches requests that
     include query strings. You can ignore any query strings when caching,
     bypass caching to prevent requests that contain query strings from being
     cached, or cache every request with a unique URL. Possible values include:
     'IgnoreQueryString', 'BypassCaching', 'UseQueryString', 'NotSet'
    :type query_string_caching_behavior: str or
     ~azure.mgmt.cdn.models.QueryStringCachingBehavior
    :param optimization_type: Specifies what scenario the customer wants this
     CDN endpoint to optimize for, e.g. Download, Media services. With this
     information, CDN can apply scenario driven optimization. Possible values
     include: 'GeneralWebDelivery', 'GeneralMediaStreaming',
     'VideoOnDemandMediaStreaming', 'LargeFileDownload',
     'DynamicSiteAcceleration'
    :type optimization_type: str or ~azure.mgmt.cdn.models.OptimizationType
    :param probe_path: Path to a file hosted on the origin which helps
     accelerate delivery of the dynamic content and calculate the most optimal
     routes for the CDN. This is relative to the origin path.
    :type probe_path: str
    :param geo_filters: List of rules defining the user's geo access within a
     CDN endpoint. Each geo filter defines an access rule to a specified path or
     content, e.g. block APAC for path /pictures/
    :type geo_filters: list[~azure.mgmt.cdn.models.GeoFilter]
    :param delivery_policy: A policy that specifies the delivery rules to be
     used for an endpoint.
    :type delivery_policy:
     ~azure.mgmt.cdn.models.EndpointPropertiesUpdateParametersDeliveryPolicy
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'origin_host_header': {'key': 'properties.originHostHeader', 'type': 'str'},
        'origin_path': {'key': 'properties.originPath', 'type': 'str'},
        'content_types_to_compress': {'key': 'properties.contentTypesToCompress', 'type': '[str]'},
        'is_compression_enabled': {'key': 'properties.isCompressionEnabled', 'type': 'bool'},
        'is_http_allowed': {'key': 'properties.isHttpAllowed', 'type': 'bool'},
        'is_https_allowed': {'key': 'properties.isHttpsAllowed', 'type': 'bool'},
        'query_string_caching_behavior': {'key': 'properties.queryStringCachingBehavior', 'type': 'QueryStringCachingBehavior'},
        'optimization_type': {'key': 'properties.optimizationType', 'type': 'str'},
        'probe_path': {'key': 'properties.probePath', 'type': 'str'},
        'geo_filters': {'key': 'properties.geoFilters', 'type': '[GeoFilter]'},
        'delivery_policy': {'key': 'properties.deliveryPolicy', 'type': 'EndpointPropertiesUpdateParametersDeliveryPolicy'},
    }

    def __init__(self, **kwargs):
        super(EndpointUpdateParameters, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.origin_host_header = kwargs.get('origin_host_header', None)
        self.origin_path = kwargs.get('origin_path', None)
        self.content_types_to_compress = kwargs.get('content_types_to_compress', None)
        self.is_compression_enabled = kwargs.get('is_compression_enabled', None)
        self.is_http_allowed = kwargs.get('is_http_allowed', None)
        self.is_https_allowed = kwargs.get('is_https_allowed', None)
        self.query_string_caching_behavior = kwargs.get('query_string_caching_behavior', None)
        self.optimization_type = kwargs.get('optimization_type', None)
        self.probe_path = kwargs.get('probe_path', None)
        self.geo_filters = kwargs.get('geo_filters', None)
        self.delivery_policy = kwargs.get('delivery_policy', None)
