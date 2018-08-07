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


class QuotaCapability(Model):
    """The regional quota capability.

    :param regional_quotas: The list of region quota capabilities.
    :type regional_quotas:
     list[~azure.mgmt.hdinsight.models.RegionalQuotaCapability]
    """

    _attribute_map = {
        'regional_quotas': {'key': 'regionalQuotas', 'type': '[RegionalQuotaCapability]'},
    }

    def __init__(self, regional_quotas=None):
        super(QuotaCapability, self).__init__()
        self.regional_quotas = regional_quotas
