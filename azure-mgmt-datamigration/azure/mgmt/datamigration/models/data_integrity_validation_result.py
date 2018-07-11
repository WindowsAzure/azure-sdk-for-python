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


class DataIntegrityValidationResult(Model):
    """Results for checksum based Data Integrity validation results.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar failed_objects: List of failed table names of source and target pair
    :vartype failed_objects: dict[str, str]
    :ivar validation_errors: List of errors that happened while performing
     data integrity validation
    :vartype validation_errors:
     ~azure.mgmt.datamigration.models.ValidationError
    """

    _validation = {
        'failed_objects': {'readonly': True},
        'validation_errors': {'readonly': True},
    }

    _attribute_map = {
        'failed_objects': {'key': 'failedObjects', 'type': '{str}'},
        'validation_errors': {'key': 'validationErrors', 'type': 'ValidationError'},
    }

    def __init__(self, **kwargs):
        super(DataIntegrityValidationResult, self).__init__(**kwargs)
        self.failed_objects = None
        self.validation_errors = None
