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


class SamplingSettings(Model):
    """Sampling settings for Diagnostic.

    :param sampling_type: Sampling type. Possible values include: 'fixed'
    :type sampling_type: str or ~azure.mgmt.apimanagement.models.SamplingType
    :param percentage: Rate of sampling for fixed-rate sampling.
    :type percentage: float
    """

    _validation = {
        'percentage': {'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'sampling_type': {'key': 'samplingType', 'type': 'str'},
        'percentage': {'key': 'percentage', 'type': 'float'},
    }

    def __init__(self, *, sampling_type=None, percentage: float=None, **kwargs) -> None:
        super(SamplingSettings, self).__init__(**kwargs)
        self.sampling_type = sampling_type
        self.percentage = percentage
