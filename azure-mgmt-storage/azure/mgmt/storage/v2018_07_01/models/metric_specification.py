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
    """Metric specification of operation.

    :param name: Name of metric specification.
    :type name: str
    :param display_name: Display name of metric specification.
    :type display_name: str
    :param display_description: Display description of metric specification.
    :type display_description: str
    :param unit: Unit could be Bytes or Count.
    :type unit: str
    :param dimensions: Dimensions of blobs, including blob type and access
     tier.
    :type dimensions: list[~azure.mgmt.storage.v2018_07_01.models.Dimension]
    :param aggregation_type: Aggregation type could be Average.
    :type aggregation_type: str
    :param fill_gap_with_zero: The property to decide fill gap with zero or
     not.
    :type fill_gap_with_zero: bool
    :param category: The category this metric specification belong to, could
     be Capacity.
    :type category: str
    :param resource_id_dimension_name_override: Account Resource Id.
    :type resource_id_dimension_name_override: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'display_description': {'key': 'displayDescription', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[Dimension]'},
        'aggregation_type': {'key': 'aggregationType', 'type': 'str'},
        'fill_gap_with_zero': {'key': 'fillGapWithZero', 'type': 'bool'},
        'category': {'key': 'category', 'type': 'str'},
        'resource_id_dimension_name_override': {'key': 'resourceIdDimensionNameOverride', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MetricSpecification, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.display_description = kwargs.get('display_description', None)
        self.unit = kwargs.get('unit', None)
        self.dimensions = kwargs.get('dimensions', None)
        self.aggregation_type = kwargs.get('aggregation_type', None)
        self.fill_gap_with_zero = kwargs.get('fill_gap_with_zero', None)
        self.category = kwargs.get('category', None)
        self.resource_id_dimension_name_override = kwargs.get('resource_id_dimension_name_override', None)
