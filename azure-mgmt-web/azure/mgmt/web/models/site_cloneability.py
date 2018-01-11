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


class SiteCloneability(Model):
    """Represents whether or not an app is cloneable.

    :param result: Name of app. Possible values include: 'Cloneable',
     'PartiallyCloneable', 'NotCloneable'
    :type result: str or ~azure.mgmt.web.models.CloneAbilityResult
    :param blocking_features: List of features enabled on app that prevent
     cloning.
    :type blocking_features:
     list[~azure.mgmt.web.models.SiteCloneabilityCriterion]
    :param unsupported_features: List of features enabled on app that are
     non-blocking but cannot be cloned. The app can still be cloned
     but the features in this list will not be set up on cloned app.
    :type unsupported_features:
     list[~azure.mgmt.web.models.SiteCloneabilityCriterion]
    :param blocking_characteristics: List of blocking application
     characteristics.
    :type blocking_characteristics:
     list[~azure.mgmt.web.models.SiteCloneabilityCriterion]
    """

    _attribute_map = {
        'result': {'key': 'result', 'type': 'CloneAbilityResult'},
        'blocking_features': {'key': 'blockingFeatures', 'type': '[SiteCloneabilityCriterion]'},
        'unsupported_features': {'key': 'unsupportedFeatures', 'type': '[SiteCloneabilityCriterion]'},
        'blocking_characteristics': {'key': 'blockingCharacteristics', 'type': '[SiteCloneabilityCriterion]'},
    }

    def __init__(self, result=None, blocking_features=None, unsupported_features=None, blocking_characteristics=None):
        super(SiteCloneability, self).__init__()
        self.result = result
        self.blocking_features = blocking_features
        self.unsupported_features = unsupported_features
        self.blocking_characteristics = blocking_characteristics
