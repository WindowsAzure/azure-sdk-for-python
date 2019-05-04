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


class OperationMetricSpecification(Model):
    """Details about an operation related to metrics.

    :param name: The name of the metric.
    :type name: str
    :param display_name: Localized display name of the metric.
    :type display_name: str
    :param display_description: The description of the metric.
    :type display_description: str
    :param unit: The unit that the metric is measured in.
    :type unit: str
    :param aggregation_type: The type of metric aggregation.
    :type aggregation_type: str
    :param enable_regional_mdm_account: Whether or not the service is using
     regional MDM accounts.
    :type enable_regional_mdm_account: str
    :param source_mdm_account: The name of the MDM account.
    :type source_mdm_account: str
    :param source_mdm_namespace: The name of the MDM namespace.
    :type source_mdm_namespace: str
    :param availabilities: Defines how often data for metrics becomes
     available.
    :type availabilities:
     list[~azure.mgmt.datafactory.models.OperationMetricAvailability]
    :param dimensions: Defines the metric dimension.
    :type dimensions:
     list[~azure.mgmt.datafactory.models.OperationMetricDimension]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'display_description': {'key': 'displayDescription', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'aggregation_type': {'key': 'aggregationType', 'type': 'str'},
        'enable_regional_mdm_account': {'key': 'enableRegionalMdmAccount', 'type': 'str'},
        'source_mdm_account': {'key': 'sourceMdmAccount', 'type': 'str'},
        'source_mdm_namespace': {'key': 'sourceMdmNamespace', 'type': 'str'},
        'availabilities': {'key': 'availabilities', 'type': '[OperationMetricAvailability]'},
        'dimensions': {'key': 'dimensions', 'type': '[OperationMetricDimension]'},
    }

    def __init__(self, *, name: str=None, display_name: str=None, display_description: str=None, unit: str=None, aggregation_type: str=None, enable_regional_mdm_account: str=None, source_mdm_account: str=None, source_mdm_namespace: str=None, availabilities=None, dimensions=None, **kwargs) -> None:
        super(OperationMetricSpecification, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.display_description = display_description
        self.unit = unit
        self.aggregation_type = aggregation_type
        self.enable_regional_mdm_account = enable_regional_mdm_account
        self.source_mdm_account = source_mdm_account
        self.source_mdm_namespace = source_mdm_namespace
        self.availabilities = availabilities
        self.dimensions = dimensions
