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


class ElasticPoolUpdate(Model):
    """An elastic pool update.

    :param sku:
    :type sku: ~azure.mgmt.sql.models.Sku
    :param max_size_bytes: The storage limit for the database elastic pool in
     bytes.
    :type max_size_bytes: long
    :param per_database_settings: The per database settings for the elastic
     pool.
    :type per_database_settings:
     ~azure.mgmt.sql.models.ElasticPoolPerDatabaseSettings
    :param zone_redundant: Whether or not this elastic pool is zone redundant,
     which means the replicas of this elastic pool will be spread across
     multiple availability zones.
    :type zone_redundant: bool
    :param license_type: The license type to apply for this elastic pool.
     Possible values include: 'LicenseIncluded', 'BasePrice'
    :type license_type: str or ~azure.mgmt.sql.models.ElasticPoolLicenseType
    :param tags: Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'max_size_bytes': {'key': 'properties.maxSizeBytes', 'type': 'long'},
        'per_database_settings': {'key': 'properties.perDatabaseSettings', 'type': 'ElasticPoolPerDatabaseSettings'},
        'zone_redundant': {'key': 'properties.zoneRedundant', 'type': 'bool'},
        'license_type': {'key': 'properties.licenseType', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(ElasticPoolUpdate, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.max_size_bytes = kwargs.get('max_size_bytes', None)
        self.per_database_settings = kwargs.get('per_database_settings', None)
        self.zone_redundant = kwargs.get('zone_redundant', None)
        self.license_type = kwargs.get('license_type', None)
        self.tags = kwargs.get('tags', None)
