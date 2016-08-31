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


class RedisProperties(Model):
    """Properties supplied to CreateOrUpdate redis operation.

    :param redis_version: RedisVersion parameter has been deprecated. As
     such, it is no longer necessary to provide this parameter and any value
     specified is ignored.
    :type redis_version: str
    :param sku: What sku of redis cache to deploy.
    :type sku: :class:`Sku <azure.mgmt.redis.models.Sku>`
    :param redis_configuration: All Redis Settings. Few possible keys:
     rdb-backup-enabled,rdb-storage-connection-string,rdb-backup-frequency,maxmemory-delta,maxmemory-policy,notify-keyspace-events,maxmemory-samples,slowlog-log-slower-than,slowlog-max-len,list-max-ziplist-entries,list-max-ziplist-value,hash-max-ziplist-entries,hash-max-ziplist-value,set-max-intset-entries,zset-max-ziplist-entries,zset-max-ziplist-value
     etc.
    :type redis_configuration: dict
    :param enable_non_ssl_port: If the value is true, then the non-ssl redis
     server port (6379) will be enabled.
    :type enable_non_ssl_port: bool
    :param tenant_settings: tenantSettings
    :type tenant_settings: dict
    :param shard_count: The number of shards to be created on a Premium
     Cluster Cache.
    :type shard_count: int
    :param subnet_id: The full resource ID of a subnet in a virtual network
     to deploy the redis cache in. Example format:
     /subscriptions/{subid}/resourceGroups/{resourceGroupName}/Microsoft.{Network|ClassicNetwork}/VirtualNetworks/vnet1/subnets/subnet1
    :type subnet_id: str
    :param static_ip: Required when deploying a redis cache inside an
     existing Azure Virtual Network.
    :type static_ip: str
    """ 

    _validation = {
        'sku': {'required': True},
        'subnet_id': {'pattern': '^/subscriptions/[^/]*/resourceGroups/[^/]*/providers/Microsoft.(ClassicNetwork|Network)/virtualNetworks/[^/]*/subnets/[^/]*$'},
        'static_ip': {'pattern': '^\d+\.\d+\.\d+\.\d+$'},
    }

    _attribute_map = {
        'redis_version': {'key': 'redisVersion', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'redis_configuration': {'key': 'redisConfiguration', 'type': '{str}'},
        'enable_non_ssl_port': {'key': 'enableNonSslPort', 'type': 'bool'},
        'tenant_settings': {'key': 'tenantSettings', 'type': '{str}'},
        'shard_count': {'key': 'shardCount', 'type': 'int'},
        'subnet_id': {'key': 'subnetId', 'type': 'str'},
        'static_ip': {'key': 'staticIP', 'type': 'str'},
    }

    def __init__(self, sku, redis_version=None, redis_configuration=None, enable_non_ssl_port=None, tenant_settings=None, shard_count=None, subnet_id=None, static_ip=None):
        self.redis_version = redis_version
        self.sku = sku
        self.redis_configuration = redis_configuration
        self.enable_non_ssl_port = enable_non_ssl_port
        self.tenant_settings = tenant_settings
        self.shard_count = shard_count
        self.subnet_id = subnet_id
        self.static_ip = static_ip
