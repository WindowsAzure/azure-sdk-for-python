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


class AzureWorkloadContainerExtendedInfo(Model):
    """Extended information of the container.

    :param host_server_name: Host Os Name in case of Stand Alone and Cluster
     Name in case of distributed container.
    :type host_server_name: str
    :param inquiry_info: Inquiry Status for the container.
    :type inquiry_info: ~azure.mgmt.recoveryservicesbackup.models.InquiryInfo
    :param nodes_list: List of the nodes in case of distributed container.
    :type nodes_list:
     list[~azure.mgmt.recoveryservicesbackup.models.DistributedNodesInfo]
    """

    _attribute_map = {
        'host_server_name': {'key': 'hostServerName', 'type': 'str'},
        'inquiry_info': {'key': 'inquiryInfo', 'type': 'InquiryInfo'},
        'nodes_list': {'key': 'nodesList', 'type': '[DistributedNodesInfo]'},
    }

    def __init__(self, **kwargs):
        super(AzureWorkloadContainerExtendedInfo, self).__init__(**kwargs)
        self.host_server_name = kwargs.get('host_server_name', None)
        self.inquiry_info = kwargs.get('inquiry_info', None)
        self.nodes_list = kwargs.get('nodes_list', None)
