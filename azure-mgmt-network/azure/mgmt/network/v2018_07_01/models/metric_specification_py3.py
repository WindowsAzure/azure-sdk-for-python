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


class MetricSpecification(Model):
    """Description of metrics specification.

    :param name: The name of the metric.
    :type name: str
    :param display_name: The display name of the metric.
    :type display_name: str
    :param display_description: The description of the metric.
    :type display_description: str
    :param unit: Units the metric to be displayed in.
    :type unit: str
    :param aggregation_type: The aggregation type.
    :type aggregation_type: str
    :param availabilities: List of availability.
    :type availabilities:
     list[~azure.mgmt.network.v2018_07_01.models.Availability]
    :param enable_regional_mdm_account: Whether regional MDM account enabled.
    :type enable_regional_mdm_account: bool
    :param fill_gap_with_zero: Whether gaps would be filled with zeros.
    :type fill_gap_with_zero: bool
    :param metric_filter_pattern: Pattern for the filter of the metric.
    :type metric_filter_pattern: str
    :param dimensions: List of dimensions.
    :type dimensions: list[~azure.mgmt.network.v2018_07_01.models.Dimension]
    :param is_internal: Whether the metric is internal.
    :type is_internal: bool
    :param source_mdm_account: The source MDM account.
    :type source_mdm_account: str
    :param source_mdm_namespace: The source MDM namespace.
    :type source_mdm_namespace: str
    :param resource_id_dimension_name_override: The resource Id dimension name
     override.
    :type resource_id_dimension_name_override: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'display_description': {'key': 'displayDescription', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'aggregation_type': {'key': 'aggregationType', 'type': 'str'},
        'availabilities': {'key': 'availabilities', 'type': '[Availability]'},
        'enable_regional_mdm_account': {'key': 'enableRegionalMdmAccount', 'type': 'bool'},
        'fill_gap_with_zero': {'key': 'fillGapWithZero', 'type': 'bool'},
        'metric_filter_pattern': {'key': 'metricFilterPattern', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[Dimension]'},
        'is_internal': {'key': 'isInternal', 'type': 'bool'},
        'source_mdm_account': {'key': 'sourceMdmAccount', 'type': 'str'},
        'source_mdm_namespace': {'key': 'sourceMdmNamespace', 'type': 'str'},
        'resource_id_dimension_name_override': {'key': 'resourceIdDimensionNameOverride', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, display_name: str=None, display_description: str=None, unit: str=None, aggregation_type: str=None, availabilities=None, enable_regional_mdm_account: bool=None, fill_gap_with_zero: bool=None, metric_filter_pattern: str=None, dimensions=None, is_internal: bool=None, source_mdm_account: str=None, source_mdm_namespace: str=None, resource_id_dimension_name_override: str=None, **kwargs) -> None:
        super(MetricSpecification, self).__init__(**kwargs)
        self.name = name
        self.display_name = display_name
        self.display_description = display_description
        self.unit = unit
        self.aggregation_type = aggregation_type
        self.availabilities = availabilities
        self.enable_regional_mdm_account = enable_regional_mdm_account
        self.fill_gap_with_zero = fill_gap_with_zero
        self.metric_filter_pattern = metric_filter_pattern
        self.dimensions = dimensions
        self.is_internal = is_internal
        self.source_mdm_account = source_mdm_account
        self.source_mdm_namespace = source_mdm_namespace
        self.resource_id_dimension_name_override = resource_id_dimension_name_override
