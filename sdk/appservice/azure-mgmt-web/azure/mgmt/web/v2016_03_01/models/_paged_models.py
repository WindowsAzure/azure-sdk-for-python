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

from msrest.paging import Paged


class CertificatePaged(Paged):
    """
    A paging container for iterating over a list of :class:`Certificate <azure.mgmt.web.v2016_03_01.models.Certificate>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Certificate]'}
    }

    def __init__(self, *args, **kwargs):

        super(CertificatePaged, self).__init__(*args, **kwargs)
class DeletedSitePaged(Paged):
    """
    A paging container for iterating over a list of :class:`DeletedSite <azure.mgmt.web.v2016_03_01.models.DeletedSite>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DeletedSite]'}
    }

    def __init__(self, *args, **kwargs):

        super(DeletedSitePaged, self).__init__(*args, **kwargs)
class DetectorResponsePaged(Paged):
    """
    A paging container for iterating over a list of :class:`DetectorResponse <azure.mgmt.web.v2016_03_01.models.DetectorResponse>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DetectorResponse]'}
    }

    def __init__(self, *args, **kwargs):

        super(DetectorResponsePaged, self).__init__(*args, **kwargs)
class DiagnosticCategoryPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DiagnosticCategory <azure.mgmt.web.v2016_03_01.models.DiagnosticCategory>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DiagnosticCategory]'}
    }

    def __init__(self, *args, **kwargs):

        super(DiagnosticCategoryPaged, self).__init__(*args, **kwargs)
class AnalysisDefinitionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`AnalysisDefinition <azure.mgmt.web.v2016_03_01.models.AnalysisDefinition>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[AnalysisDefinition]'}
    }

    def __init__(self, *args, **kwargs):

        super(AnalysisDefinitionPaged, self).__init__(*args, **kwargs)
class DetectorDefinitionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`DetectorDefinition <azure.mgmt.web.v2016_03_01.models.DetectorDefinition>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[DetectorDefinition]'}
    }

    def __init__(self, *args, **kwargs):

        super(DetectorDefinitionPaged, self).__init__(*args, **kwargs)
class ApplicationStackPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ApplicationStack <azure.mgmt.web.v2016_03_01.models.ApplicationStack>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ApplicationStack]'}
    }

    def __init__(self, *args, **kwargs):

        super(ApplicationStackPaged, self).__init__(*args, **kwargs)
class CsmOperationDescriptionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`CsmOperationDescription <azure.mgmt.web.v2016_03_01.models.CsmOperationDescription>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[CsmOperationDescription]'}
    }

    def __init__(self, *args, **kwargs):

        super(CsmOperationDescriptionPaged, self).__init__(*args, **kwargs)
class RecommendationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Recommendation <azure.mgmt.web.v2016_03_01.models.Recommendation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Recommendation]'}
    }

    def __init__(self, *args, **kwargs):

        super(RecommendationPaged, self).__init__(*args, **kwargs)
class ResourceHealthMetadataPaged(Paged):
    """
    A paging container for iterating over a list of :class:`ResourceHealthMetadata <azure.mgmt.web.v2016_03_01.models.ResourceHealthMetadata>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[ResourceHealthMetadata]'}
    }

    def __init__(self, *args, **kwargs):

        super(ResourceHealthMetadataPaged, self).__init__(*args, **kwargs)
class SourceControlPaged(Paged):
    """
    A paging container for iterating over a list of :class:`SourceControl <azure.mgmt.web.v2016_03_01.models.SourceControl>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SourceControl]'}
    }

    def __init__(self, *args, **kwargs):

        super(SourceControlPaged, self).__init__(*args, **kwargs)
class GeoRegionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`GeoRegion <azure.mgmt.web.v2016_03_01.models.GeoRegion>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[GeoRegion]'}
    }

    def __init__(self, *args, **kwargs):

        super(GeoRegionPaged, self).__init__(*args, **kwargs)
class IdentifierPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Identifier <azure.mgmt.web.v2016_03_01.models.Identifier>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Identifier]'}
    }

    def __init__(self, *args, **kwargs):

        super(IdentifierPaged, self).__init__(*args, **kwargs)
class PremierAddOnOfferPaged(Paged):
    """
    A paging container for iterating over a list of :class:`PremierAddOnOffer <azure.mgmt.web.v2016_03_01.models.PremierAddOnOffer>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PremierAddOnOffer]'}
    }

    def __init__(self, *args, **kwargs):

        super(PremierAddOnOfferPaged, self).__init__(*args, **kwargs)
class BillingMeterPaged(Paged):
    """
    A paging container for iterating over a list of :class:`BillingMeter <azure.mgmt.web.v2016_03_01.models.BillingMeter>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[BillingMeter]'}
    }

    def __init__(self, *args, **kwargs):

        super(BillingMeterPaged, self).__init__(*args, **kwargs)
