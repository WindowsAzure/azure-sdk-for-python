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

from .proxy_resource_py3 import ProxyResource


class RecommendedElasticPool(ProxyResource):
    """Represents a recommended elastic pool.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar database_edition: The edition of the recommended elastic pool. The
     ElasticPoolEdition enumeration contains all the valid editions. Possible
     values include: 'Basic', 'Standard', 'Premium', 'GeneralPurpose',
     'BusinessCritical'
    :vartype database_edition: str or
     ~azure.mgmt.sql.models.ElasticPoolEdition
    :param dtu: The DTU for the recommended elastic pool.
    :type dtu: float
    :param database_dtu_min: The minimum DTU for the database.
    :type database_dtu_min: float
    :param database_dtu_max: The maximum DTU for the database.
    :type database_dtu_max: float
    :param storage_mb: Gets storage size in megabytes.
    :type storage_mb: float
    :ivar observation_period_start: The observation period start (ISO8601
     format).
    :vartype observation_period_start: datetime
    :ivar observation_period_end: The observation period start (ISO8601
     format).
    :vartype observation_period_end: datetime
    :ivar max_observed_dtu: Gets maximum observed DTU.
    :vartype max_observed_dtu: float
    :ivar max_observed_storage_mb: Gets maximum observed storage in megabytes.
    :vartype max_observed_storage_mb: float
    :ivar databases: The list of databases in this pool. Expanded property
    :vartype databases: list[~azure.mgmt.sql.models.TrackedResource]
    :ivar metrics: The list of databases housed in the server. Expanded
     property
    :vartype metrics:
     list[~azure.mgmt.sql.models.RecommendedElasticPoolMetric]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'database_edition': {'readonly': True},
        'observation_period_start': {'readonly': True},
        'observation_period_end': {'readonly': True},
        'max_observed_dtu': {'readonly': True},
        'max_observed_storage_mb': {'readonly': True},
        'databases': {'readonly': True},
        'metrics': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'database_edition': {'key': 'properties.databaseEdition', 'type': 'str'},
        'dtu': {'key': 'properties.dtu', 'type': 'float'},
        'database_dtu_min': {'key': 'properties.databaseDtuMin', 'type': 'float'},
        'database_dtu_max': {'key': 'properties.databaseDtuMax', 'type': 'float'},
        'storage_mb': {'key': 'properties.storageMB', 'type': 'float'},
        'observation_period_start': {'key': 'properties.observationPeriodStart', 'type': 'iso-8601'},
        'observation_period_end': {'key': 'properties.observationPeriodEnd', 'type': 'iso-8601'},
        'max_observed_dtu': {'key': 'properties.maxObservedDtu', 'type': 'float'},
        'max_observed_storage_mb': {'key': 'properties.maxObservedStorageMB', 'type': 'float'},
        'databases': {'key': 'properties.databases', 'type': '[TrackedResource]'},
        'metrics': {'key': 'properties.metrics', 'type': '[RecommendedElasticPoolMetric]'},
    }

    def __init__(self, *, dtu: float=None, database_dtu_min: float=None, database_dtu_max: float=None, storage_mb: float=None, **kwargs) -> None:
        super(RecommendedElasticPool, self).__init__(**kwargs)
        self.database_edition = None
        self.dtu = dtu
        self.database_dtu_min = database_dtu_min
        self.database_dtu_max = database_dtu_max
        self.storage_mb = storage_mb
        self.observation_period_start = None
        self.observation_period_end = None
        self.max_observed_dtu = None
        self.max_observed_storage_mb = None
        self.databases = None
        self.metrics = None
