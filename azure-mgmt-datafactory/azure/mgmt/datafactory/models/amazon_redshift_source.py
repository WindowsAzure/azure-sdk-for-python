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

from .copy_source import CopySource


class AmazonRedshiftSource(CopySource):
    """A copy activity source for Amazon Redshift Source.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param source_retry_count: Source retry count. Type: integer (or
     Expression with resultType integer).
    :type source_retry_count: object
    :param source_retry_wait: Source retry wait. Type: string (or Expression
     with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type source_retry_wait: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param query: Database query. Type: string (or Expression with resultType
     string).
    :type query: object
    :param redshift_unload_settings: The Amazon S3 settings needed for the
     interim Amazon S3 when copying from Amazon Redshift with unload. With
     this, data from Amazon Redshift source will be unloaded into S3 first and
     then copied into the targeted sink from the interim S3.
    :type redshift_unload_settings:
     ~azure.mgmt.datafactory.models.RedshiftUnloadSettings
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'source_retry_count': {'key': 'sourceRetryCount', 'type': 'object'},
        'source_retry_wait': {'key': 'sourceRetryWait', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'query': {'key': 'query', 'type': 'object'},
        'redshift_unload_settings': {'key': 'redshiftUnloadSettings', 'type': 'RedshiftUnloadSettings'},
    }

    def __init__(self, **kwargs):
        super(AmazonRedshiftSource, self).__init__(**kwargs)
        self.query = kwargs.get('query', None)
        self.redshift_unload_settings = kwargs.get('redshift_unload_settings', None)
        self.type = 'AmazonRedshiftSource'
