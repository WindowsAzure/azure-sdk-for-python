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


class ApplicationInsightsComponentAvailableFeatures(Model):
    """An Application Insights component available features.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar result: A list of Application Insights component feature.
    :vartype result:
     list[~azure.mgmt.applicationinsights.models.ApplicationInsightsComponentFeature]
    """

    _validation = {
        'result': {'readonly': True},
    }

    _attribute_map = {
        'result': {'key': 'Result', 'type': '[ApplicationInsightsComponentFeature]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ApplicationInsightsComponentAvailableFeatures, self).__init__(**kwargs)
        self.result = None
