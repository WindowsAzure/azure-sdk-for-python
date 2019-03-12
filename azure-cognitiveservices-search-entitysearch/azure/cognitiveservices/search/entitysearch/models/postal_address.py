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

from .structured_value import StructuredValue


class PostalAddress(StructuredValue):
    """Defines a postal address.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param _type: Required. Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :ivar contractual_rules: A list of rules that you must adhere to if you
     display the item.
    :vartype contractual_rules:
     list[~azure.cognitiveservices.search.entitysearch.models.ContractualRulesContractualRule]
    :ivar web_search_url: The URL To Bing's search result for this item.
    :vartype web_search_url: str
    :ivar name: The name of the thing represented by this object.
    :vartype name: str
    :ivar url: The URL to get more information about the thing represented by
     this object.
    :vartype url: str
    :ivar image:
    :vartype image:
     ~azure.cognitiveservices.search.entitysearch.models.ImageObject
    :ivar description: A short description of the item.
    :vartype description: str
    :ivar entity_presentation_info: Additional information about the entity
     such as hints that you can use to determine the entity's type. To
     determine the entity's type, use the entityScenario and entityTypeHint
     fields.
    :vartype entity_presentation_info:
     ~azure.cognitiveservices.search.entitysearch.models.EntitiesEntityPresentationInfo
    :ivar bing_id: An ID that uniquely identifies this item.
    :vartype bing_id: str
    :ivar street_address:
    :vartype street_address: str
    :ivar address_locality: The city where the street address is located. For
     example, Seattle.
    :vartype address_locality: str
    :ivar address_subregion:
    :vartype address_subregion: str
    :ivar address_region: The state or province code where the street address
     is located. This could be the two-letter code. For example, WA, or the
     full name , Washington.
    :vartype address_region: str
    :ivar postal_code: The zip code or postal code where the street address is
     located. For example, 98052.
    :vartype postal_code: str
    :ivar post_office_box_number:
    :vartype post_office_box_number: str
    :ivar address_country: The country/region where the street address is
     located. This could be the two-letter ISO code. For example, US, or the
     full name, United States.
    :vartype address_country: str
    :ivar country_iso: The two letter ISO code of this countr. For example,
     US.
    :vartype country_iso: str
    :ivar neighborhood: The neighborhood where the street address is located.
     For example, Westlake.
    :vartype neighborhood: str
    :ivar address_region_abbreviation: Region Abbreviation. For example, WA.
    :vartype address_region_abbreviation: str
    :ivar text: The complete address. For example, 2100 Westlake Ave N,
     Bellevue, WA 98052.
    :vartype text: str
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'contractual_rules': {'readonly': True},
        'web_search_url': {'readonly': True},
        'name': {'readonly': True},
        'url': {'readonly': True},
        'image': {'readonly': True},
        'description': {'readonly': True},
        'entity_presentation_info': {'readonly': True},
        'bing_id': {'readonly': True},
        'street_address': {'readonly': True},
        'address_locality': {'readonly': True},
        'address_subregion': {'readonly': True},
        'address_region': {'readonly': True},
        'postal_code': {'readonly': True},
        'post_office_box_number': {'readonly': True},
        'address_country': {'readonly': True},
        'country_iso': {'readonly': True},
        'neighborhood': {'readonly': True},
        'address_region_abbreviation': {'readonly': True},
        'text': {'readonly': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'contractual_rules': {'key': 'contractualRules', 'type': '[ContractualRulesContractualRule]'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'image': {'key': 'image', 'type': 'ImageObject'},
        'description': {'key': 'description', 'type': 'str'},
        'entity_presentation_info': {'key': 'entityPresentationInfo', 'type': 'EntitiesEntityPresentationInfo'},
        'bing_id': {'key': 'bingId', 'type': 'str'},
        'street_address': {'key': 'streetAddress', 'type': 'str'},
        'address_locality': {'key': 'addressLocality', 'type': 'str'},
        'address_subregion': {'key': 'addressSubregion', 'type': 'str'},
        'address_region': {'key': 'addressRegion', 'type': 'str'},
        'postal_code': {'key': 'postalCode', 'type': 'str'},
        'post_office_box_number': {'key': 'postOfficeBoxNumber', 'type': 'str'},
        'address_country': {'key': 'addressCountry', 'type': 'str'},
        'country_iso': {'key': 'countryIso', 'type': 'str'},
        'neighborhood': {'key': 'neighborhood', 'type': 'str'},
        'address_region_abbreviation': {'key': 'addressRegionAbbreviation', 'type': 'str'},
        'text': {'key': 'text', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PostalAddress, self).__init__(**kwargs)
        self.street_address = None
        self.address_locality = None
        self.address_subregion = None
        self.address_region = None
        self.postal_code = None
        self.post_office_box_number = None
        self.address_country = None
        self.country_iso = None
        self.neighborhood = None
        self.address_region_abbreviation = None
        self.text = None
        self._type = 'PostalAddress'
