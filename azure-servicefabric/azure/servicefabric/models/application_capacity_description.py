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


class ApplicationCapacityDescription(Model):
    """Describes capacity information for services of this application. This
    description can be used for describing the following.
    - Reserving the capacity for the services on the nodes
    - Limiting the total number of nodes that services of this application can
    run on
    - Limiting the custom capacity metrics to limit the total consumption of
    this metric by the services of this application
    .

    :param minimum_nodes: The minimum number of nodes where Service Fabric
     will reserve capacity for this application. Note that this does not mean
     that the services of this application will be placed on all of those
     nodes. If this property is set to zero, no capacity will be reserved. The
     value of this property cannot be more than the value of the MaximumNodes
     property.
    :type minimum_nodes: long
    :param maximum_nodes: The maximum number of nodes where Service Fabric
     will reserve capacity for this application. Note that this does not mean
     that the services of this application will be placed on all of those
     nodes. By default, the value of this property is zero and it means that
     the services can be placed on any node. Default value: 0 .
    :type maximum_nodes: long
    :param application_metrics: List of application capacity metric
     description.
    :type application_metrics:
     list[~azure.servicefabric.models.ApplicationMetricDescription]
    """

    _validation = {
        'minimum_nodes': {'minimum': 0},
        'maximum_nodes': {'minimum': 0},
    }

    _attribute_map = {
        'minimum_nodes': {'key': 'MinimumNodes', 'type': 'long'},
        'maximum_nodes': {'key': 'MaximumNodes', 'type': 'long'},
        'application_metrics': {'key': 'ApplicationMetrics', 'type': '[ApplicationMetricDescription]'},
    }

    def __init__(self, **kwargs):
        super(ApplicationCapacityDescription, self).__init__(**kwargs)
        self.minimum_nodes = kwargs.get('minimum_nodes', None)
        self.maximum_nodes = kwargs.get('maximum_nodes', 0)
        self.application_metrics = kwargs.get('application_metrics', None)
