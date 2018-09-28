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


class GalleryArtifactPublishingProfileBase(Model):
    """Describes the basic gallery artifact publishing profile.

    All required parameters must be populated in order to send to Azure.

    :param target_regions: The target regions where the artifact is going to
     be published.
    :type target_regions:
     list[~azure.mgmt.compute.v2018_06_01.models.TargetRegion]
    :param source: Required.
    :type source: ~azure.mgmt.compute.v2018_06_01.models.GalleryArtifactSource
    """

    _validation = {
        'source': {'required': True},
    }

    _attribute_map = {
        'target_regions': {'key': 'targetRegions', 'type': '[TargetRegion]'},
        'source': {'key': 'source', 'type': 'GalleryArtifactSource'},
    }

    def __init__(self, **kwargs):
        super(GalleryArtifactPublishingProfileBase, self).__init__(**kwargs)
        self.target_regions = kwargs.get('target_regions', None)
        self.source = kwargs.get('source', None)
