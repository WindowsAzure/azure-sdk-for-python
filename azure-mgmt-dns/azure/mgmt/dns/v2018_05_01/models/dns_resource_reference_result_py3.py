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


class DnsResourceReferenceResult(Model):
    """DnsResourceReferenceResult.

    :param dns_resource_references: The result of dns resource reference
     request. A list of dns resource references for each of the azure resource
     in the request
    :type dns_resource_references:
     list[~azure.mgmt.dns.v2018_05_01.models.DnsResourceReference]
    """

    _attribute_map = {
        'dns_resource_references': {'key': 'properties.dnsResourceReferences', 'type': '[DnsResourceReference]'},
    }

    def __init__(self, *, dns_resource_references=None, **kwargs) -> None:
        super(DnsResourceReferenceResult, self).__init__(**kwargs)
        self.dns_resource_references = dns_resource_references
