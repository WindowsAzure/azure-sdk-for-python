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


class DomainRecommendationSearchParameters(Model):
    """Domain recommendation search parameters.

    :param keywords: Keywords to be used for generating domain
     recommendations.
    :type keywords: str
    :param max_domain_recommendations: Maximum number of recommendations.
    :type max_domain_recommendations: int
    """

    _attribute_map = {
        'keywords': {'key': 'keywords', 'type': 'str'},
        'max_domain_recommendations': {'key': 'maxDomainRecommendations', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(DomainRecommendationSearchParameters, self).__init__(**kwargs)
        self.keywords = kwargs.get('keywords', None)
        self.max_domain_recommendations = kwargs.get('max_domain_recommendations', None)
