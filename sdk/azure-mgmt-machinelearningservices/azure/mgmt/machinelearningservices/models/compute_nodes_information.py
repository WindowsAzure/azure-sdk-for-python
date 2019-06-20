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


class ComputeNodesInformation(Model):
    """Compute nodes information related to a Machine Learning compute. Might
    differ for every type of compute.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AmlComputeNodesInformation

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar next_link: The continuation token.
    :vartype next_link: str
    :param compute_type: Required. Constant filled by server.
    :type compute_type: str
    """

    _validation = {
        'next_link': {'readonly': True},
        'compute_type': {'required': True},
    }

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'compute_type': {'key': 'computeType', 'type': 'str'},
    }

    _subtype_map = {
        'compute_type': {'AmlCompute': 'AmlComputeNodesInformation'}
    }

    def __init__(self, **kwargs):
        super(ComputeNodesInformation, self).__init__(**kwargs)
        self.next_link = None
        self.compute_type = None
