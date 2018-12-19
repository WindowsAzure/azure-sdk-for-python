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


class MongoDbDatabaseSettings(Model):
    """Describes how an individual MongoDB database should be migrated.

    All required parameters must be populated in order to send to Azure.

    :param collections: Required. The collections on the source database to
     migrate to the target. The keys are the unqualified names of the
     collections.
    :type collections: dict[str,
     ~azure.mgmt.datamigration.models.MongoDbCollectionSettings]
    :param target_rus: The RUs that should be configured on a CosmosDB target,
     or null to use the default, or 0 if throughput should not be provisioned
     for the database. This has no effect on non-CosmosDB targets.
    :type target_rus: int
    """

    _validation = {
        'collections': {'required': True},
    }

    _attribute_map = {
        'collections': {'key': 'collections', 'type': '{MongoDbCollectionSettings}'},
        'target_rus': {'key': 'targetRUs', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(MongoDbDatabaseSettings, self).__init__(**kwargs)
        self.collections = kwargs.get('collections', None)
        self.target_rus = kwargs.get('target_rus', None)
