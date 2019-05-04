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


class CacheExpirationActionParameters(Model):
    """Defines the parameters for the cache expiration action.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "#Microsoft.Azure.Cdn.Models.DeliveryRuleCacheExpirationActionParameters"
     .
    :vartype odatatype: str
    :param cache_behavior: Required. Caching behavior for the requests.
     Possible values include: 'BypassCache', 'Override', 'SetIfMissing'
    :type cache_behavior: str or ~azure.mgmt.cdn.models.CacheBehavior
    :ivar cache_type: Required. The level at which the content needs to be
     cached. Default value: "All" .
    :vartype cache_type: str
    :param cache_duration: The duration for which the content needs to be
     cached. Allowed format is [d.]hh:mm:ss
    :type cache_duration: str
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'cache_behavior': {'required': True},
        'cache_type': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'cache_behavior': {'key': 'cacheBehavior', 'type': 'str'},
        'cache_type': {'key': 'cacheType', 'type': 'str'},
        'cache_duration': {'key': 'cacheDuration', 'type': 'str'},
    }

    odatatype = "#Microsoft.Azure.Cdn.Models.DeliveryRuleCacheExpirationActionParameters"

    cache_type = "All"

    def __init__(self, **kwargs):
        super(CacheExpirationActionParameters, self).__init__(**kwargs)
        self.cache_behavior = kwargs.get('cache_behavior', None)
        self.cache_duration = kwargs.get('cache_duration', None)
