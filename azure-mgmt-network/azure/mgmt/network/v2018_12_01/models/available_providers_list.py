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


class AvailableProvidersList(Model):
    """List of available countries with details.

    All required parameters must be populated in order to send to Azure.

    :param countries: Required. List of available countries.
    :type countries:
     list[~azure.mgmt.network.v2018_12_01.models.AvailableProvidersListCountry]
    """

    _validation = {
        'countries': {'required': True},
    }

    _attribute_map = {
        'countries': {'key': 'countries', 'type': '[AvailableProvidersListCountry]'},
    }

    def __init__(self, **kwargs):
        super(AvailableProvidersList, self).__init__(**kwargs)
        self.countries = kwargs.get('countries', None)
