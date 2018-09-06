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


class DataSource(Model):
    """Class representing data source used by the detectors.

    :param instructions: Instrunctions if any for the data source
    :type instructions: list[str]
    :param data_source_uri: Datasource Uri Links
    :type data_source_uri: list[~azure.mgmt.web.models.NameValuePair]
    """

    _attribute_map = {
        'instructions': {'key': 'instructions', 'type': '[str]'},
        'data_source_uri': {'key': 'dataSourceUri', 'type': '[NameValuePair]'},
    }

    def __init__(self, **kwargs):
        super(DataSource, self).__init__(**kwargs)
        self.instructions = kwargs.get('instructions', None)
        self.data_source_uri = kwargs.get('data_source_uri', None)
