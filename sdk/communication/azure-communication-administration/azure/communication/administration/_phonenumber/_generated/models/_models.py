# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class AcquiredPhoneNumber(msrest.serialization.Model):
    """Represents an acquired phone number.

    All required parameters must be populated in order to send to Azure.

    :param phone_number: Required. String of the E.164 format of the phone number.
    :type phone_number: str
    :param acquired_capabilities: Required. The set of all acquired capabilities of the phone
     number.
    :type acquired_capabilities: list[str or ~azure.communication.administration.models.Capability]
    :param available_capabilities: Required. The set of all available capabilities that can be
     acquired for this phone number.
    :type available_capabilities: list[str or
     ~azure.communication.administration.models.Capability]
    :param assignment_status: The assignment status of the phone number. Conveys what type of
     entity the number is assigned to. Possible values include: "Unassigned", "Unknown",
     "UserAssigned", "ConferenceAssigned", "FirstPartyAppAssigned", "ThirdPartyAppAssigned".
    :type assignment_status: str or ~azure.communication.administration.models.AssignmentStatus
    :param place_name: The name of the place of the phone number.
    :type place_name: str
    :param activation_state: The activation state of the phone number. Can be "Activated",
     "AssignmentPending", "AssignmentFailed", "UpdatePending", "UpdateFailed". Possible values
     include: "Activated", "AssignmentPending", "AssignmentFailed", "UpdatePending", "UpdateFailed".
    :type activation_state: str or ~azure.communication.administration.models.ActivationState
    """

    _validation = {
        'phone_number': {'required': True},
        'acquired_capabilities': {'required': True},
        'available_capabilities': {'required': True},
    }

    _attribute_map = {
        'phone_number': {'key': 'phoneNumber', 'type': 'str'},
        'acquired_capabilities': {'key': 'acquiredCapabilities', 'type': '[str]'},
        'available_capabilities': {'key': 'availableCapabilities', 'type': '[str]'},
        'assignment_status': {'key': 'assignmentStatus', 'type': 'str'},
        'place_name': {'key': 'placeName', 'type': 'str'},
        'activation_state': {'key': 'activationState', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AcquiredPhoneNumber, self).__init__(**kwargs)
        self.phone_number = kwargs['phone_number']
        self.acquired_capabilities = kwargs['acquired_capabilities']
        self.available_capabilities = kwargs['available_capabilities']
        self.assignment_status = kwargs.get('assignment_status', None)
        self.place_name = kwargs.get('place_name', None)
        self.activation_state = kwargs.get('activation_state', None)


class AcquiredPhoneNumbers(msrest.serialization.Model):
    """A wrapper of list of phone numbers.

    :param phone_numbers: Represents a list of phone numbers.
    :type phone_numbers: list[~azure.communication.administration.models.AcquiredPhoneNumber]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'phone_numbers': {'key': 'phoneNumbers', 'type': '[AcquiredPhoneNumber]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AcquiredPhoneNumbers, self).__init__(**kwargs)
        self.phone_numbers = kwargs.get('phone_numbers', None)
        self.next_link = kwargs.get('next_link', None)


class AreaCodes(msrest.serialization.Model):
    """Represents a list of area codes.

    :param primary_area_codes: Represents the list of primary area codes.
    :type primary_area_codes: list[str]
    :param secondary_area_codes: Represents the list of secondary area codes.
    :type secondary_area_codes: list[str]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'primary_area_codes': {'key': 'primaryAreaCodes', 'type': '[str]'},
        'secondary_area_codes': {'key': 'secondaryAreaCodes', 'type': '[str]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AreaCodes, self).__init__(**kwargs)
        self.primary_area_codes = kwargs.get('primary_area_codes', None)
        self.secondary_area_codes = kwargs.get('secondary_area_codes', None)
        self.next_link = kwargs.get('next_link', None)


class CarrierDetails(msrest.serialization.Model):
    """Represents carrier details.

    :param name: Name of carrier details.
    :type name: str
    :param localized_name: Display name of carrier details.
    :type localized_name: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'localized_name': {'key': 'localizedName', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CarrierDetails, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.localized_name = kwargs.get('localized_name', None)


class CreateSearchOptions(msrest.serialization.Model):
    """Represents a search creation option.

    All required parameters must be populated in order to send to Azure.

    :param display_name: Required. Display name of the search.
    :type display_name: str
    :param description: Required. Description of the search.
    :type description: str
    :param phone_plan_ids: Required. The plan subtype ids from which to create the search.
    :type phone_plan_ids: list[str]
    :param area_code: Required. The area code from which to create the search.
    :type area_code: str
    :param quantity: The quantity of phone numbers to request.
    :type quantity: int
    :param location_options: The location options of the search.
    :type location_options: list[~azure.communication.administration.models.LocationOptionsDetails]
    """

    _validation = {
        'display_name': {'required': True, 'max_length': 255, 'min_length': 0},
        'description': {'required': True, 'max_length': 255, 'min_length': 0},
        'phone_plan_ids': {'required': True},
        'area_code': {'required': True},
        'quantity': {'maximum': 2147483647, 'minimum': 1},
    }

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'phone_plan_ids': {'key': 'phonePlanIds', 'type': '[str]'},
        'area_code': {'key': 'areaCode', 'type': 'str'},
        'quantity': {'key': 'quantity', 'type': 'int'},
        'location_options': {'key': 'locationOptions', 'type': '[LocationOptionsDetails]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CreateSearchOptions, self).__init__(**kwargs)
        self.display_name = kwargs['display_name']
        self.description = kwargs['description']
        self.phone_plan_ids = kwargs['phone_plan_ids']
        self.area_code = kwargs['area_code']
        self.quantity = kwargs.get('quantity', None)
        self.location_options = kwargs.get('location_options', None)


class CreateSearchResponse(msrest.serialization.Model):
    """Represents a search creation response.

    All required parameters must be populated in order to send to Azure.

    :param search_id: Required. The search id of the search that was created.
    :type search_id: str
    """

    _validation = {
        'search_id': {'required': True},
    }

    _attribute_map = {
        'search_id': {'key': 'searchId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CreateSearchResponse, self).__init__(**kwargs)
        self.search_id = kwargs['search_id']


class ErrorBody(msrest.serialization.Model):
    """Represents a service error response body.

    :param code: The error code in the error response.
    :type code: str
    :param message: The error message in the error response.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)


class ErrorResponse(msrest.serialization.Model):
    """Represents a service error response.

    :param error: Represents a service error response body.
    :type error: ~azure.communication.administration.models.ErrorBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorBody'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class LocationOptions(msrest.serialization.Model):
    """Represents a location options.

    :param label_id: The label id of the location.
    :type label_id: str
    :param label_name: The display name of the location.
    :type label_name: str
    :param options: The underlying location option details.
    :type options: list[~azure.communication.administration.models.LocationOptionsDetails]
    """

    _attribute_map = {
        'label_id': {'key': 'labelId', 'type': 'str'},
        'label_name': {'key': 'labelName', 'type': 'str'},
        'options': {'key': 'options', 'type': '[LocationOptionsDetails]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationOptions, self).__init__(**kwargs)
        self.label_id = kwargs.get('label_id', None)
        self.label_name = kwargs.get('label_name', None)
        self.options = kwargs.get('options', None)


class LocationOptionsDetails(msrest.serialization.Model):
    """Represents location options details.

    :param name: The name of the location options.
    :type name: str
    :param value: The abbreviated name of the location options.
    :type value: str
    :param location_options: The underlying location options.
    :type location_options: list[~azure.communication.administration.models.LocationOptions]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'location_options': {'key': 'locationOptions', 'type': '[LocationOptions]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationOptionsDetails, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.value = kwargs.get('value', None)
        self.location_options = kwargs.get('location_options', None)


class LocationOptionsQueries(msrest.serialization.Model):
    """Represents a list of location option queries, used for fetching area codes.

    :param location_options: Represents the underlying list of countries.
    :type location_options: list[~azure.communication.administration.models.LocationOptionsQuery]
    """

    _attribute_map = {
        'location_options': {'key': 'locationOptions', 'type': '[LocationOptionsQuery]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationOptionsQueries, self).__init__(**kwargs)
        self.location_options = kwargs.get('location_options', None)


class LocationOptionsQuery(msrest.serialization.Model):
    """Represents a location options parameter, used for fetching area codes.

    :param label_id: Represents the location option label id, returned from the GetLocationOptions
     API.
    :type label_id: str
    :param options_value: Represents the location options value, returned from the
     GetLocationOptions API.
    :type options_value: str
    """

    _attribute_map = {
        'label_id': {'key': 'labelId', 'type': 'str'},
        'options_value': {'key': 'optionsValue', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationOptionsQuery, self).__init__(**kwargs)
        self.label_id = kwargs.get('label_id', None)
        self.options_value = kwargs.get('options_value', None)


class LocationOptionsResponse(msrest.serialization.Model):
    """Represents a wrapper around a list of location options.

    :param location_options: Represents a location options.
    :type location_options: ~azure.communication.administration.models.LocationOptions
    """

    _attribute_map = {
        'location_options': {'key': 'locationOptions', 'type': 'LocationOptions'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(LocationOptionsResponse, self).__init__(**kwargs)
        self.location_options = kwargs.get('location_options', None)


class NumberConfiguration(msrest.serialization.Model):
    """Definition for number configuration.

    All required parameters must be populated in order to send to Azure.

    :param pstn_configuration: Required. Definition for pstn number configuration.
    :type pstn_configuration: ~azure.communication.administration.models.PstnConfiguration
    :param phone_number: Required. The phone number to configure.
    :type phone_number: str
    """

    _validation = {
        'pstn_configuration': {'required': True},
        'phone_number': {'required': True},
    }

    _attribute_map = {
        'pstn_configuration': {'key': 'pstnConfiguration', 'type': 'PstnConfiguration'},
        'phone_number': {'key': 'phoneNumber', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(NumberConfiguration, self).__init__(**kwargs)
        self.pstn_configuration = kwargs['pstn_configuration']
        self.phone_number = kwargs['phone_number']


class NumberConfigurationPhoneNumber(msrest.serialization.Model):
    """The phone number wrapper representing a number configuration request.

    All required parameters must be populated in order to send to Azure.

    :param phone_number: Required. The phone number in the E.164 format.
    :type phone_number: str
    """

    _validation = {
        'phone_number': {'required': True},
    }

    _attribute_map = {
        'phone_number': {'key': 'phoneNumber', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(NumberConfigurationPhoneNumber, self).__init__(**kwargs)
        self.phone_number = kwargs['phone_number']


class NumberConfigurationResponse(msrest.serialization.Model):
    """Definition for number configuration.

    All required parameters must be populated in order to send to Azure.

    :param pstn_configuration: Required. Definition for pstn number configuration.
    :type pstn_configuration: ~azure.communication.administration.models.PstnConfiguration
    """

    _validation = {
        'pstn_configuration': {'required': True},
    }

    _attribute_map = {
        'pstn_configuration': {'key': 'pstnConfiguration', 'type': 'PstnConfiguration'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(NumberConfigurationResponse, self).__init__(**kwargs)
        self.pstn_configuration = kwargs['pstn_configuration']


class NumberUpdateCapabilities(msrest.serialization.Model):
    """Represents an individual number capabilities update request.

    :param add: Capabilities to be added to a phone number.
    :type add: list[str or ~azure.communication.administration.models.Capability]
    :param remove: Capabilities to be removed from a phone number.
    :type remove: list[str or ~azure.communication.administration.models.Capability]
    """

    _attribute_map = {
        'add': {'key': 'add', 'type': '[str]'},
        'remove': {'key': 'remove', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(NumberUpdateCapabilities, self).__init__(**kwargs)
        self.add = kwargs.get('add', None)
        self.remove = kwargs.get('remove', None)


class PhoneNumberCountries(msrest.serialization.Model):
    """Represents a wrapper around a list of countries.

    :param countries: Represents the underlying list of countries.
    :type countries: list[~azure.communication.administration.models.PhoneNumberCountry]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'countries': {'key': 'countries', 'type': '[PhoneNumberCountry]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberCountries, self).__init__(**kwargs)
        self.countries = kwargs.get('countries', None)
        self.next_link = kwargs.get('next_link', None)


class PhoneNumberCountry(msrest.serialization.Model):
    """Represents a country.

    All required parameters must be populated in order to send to Azure.

    :param localized_name: Required. Represents the name of the country.
    :type localized_name: str
    :param country_code: Required. Represents the abbreviated name of the country.
    :type country_code: str
    """

    _validation = {
        'localized_name': {'required': True},
        'country_code': {'required': True},
    }

    _attribute_map = {
        'localized_name': {'key': 'localizedName', 'type': 'str'},
        'country_code': {'key': 'countryCode', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberCountry, self).__init__(**kwargs)
        self.localized_name = kwargs['localized_name']
        self.country_code = kwargs['country_code']


class PhoneNumberEntities(msrest.serialization.Model):
    """Represents a list of searches or releases, as part of the response when fetching all searches or releases.

    :param entities: The underlying list of entities.
    :type entities: list[~azure.communication.administration.models.PhoneNumberEntity]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'entities': {'key': 'entities', 'type': '[PhoneNumberEntity]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberEntities, self).__init__(**kwargs)
        self.entities = kwargs.get('entities', None)
        self.next_link = kwargs.get('next_link', None)


class PhoneNumberEntity(msrest.serialization.Model):
    """Represents a phone number entity, as part of the response when calling get all searches or releases.

    :param id: The id of the entity. It is the search id of a search. It is the release id of a
     release.
    :type id: str
    :param created_at: Date and time the entity is created.
    :type created_at: ~datetime.datetime
    :param display_name: Name of the entity.
    :type display_name: str
    :param quantity: Quantity of requested phone numbers in the entity.
    :type quantity: int
    :param quantity_obtained: Quantity of acquired phone numbers in the entity.
    :type quantity_obtained: int
    :param status: Status of the entity.
    :type status: str
    :param foc_date: The Firm Order Confirmation date of the phone number entity.
    :type foc_date: ~datetime.datetime
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'quantity': {'key': 'quantity', 'type': 'int'},
        'quantity_obtained': {'key': 'quantityObtained', 'type': 'int'},
        'status': {'key': 'status', 'type': 'str'},
        'foc_date': {'key': 'focDate', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberEntity, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.created_at = kwargs.get('created_at', None)
        self.display_name = kwargs.get('display_name', None)
        self.quantity = kwargs.get('quantity', None)
        self.quantity_obtained = kwargs.get('quantity_obtained', None)
        self.status = kwargs.get('status', None)
        self.foc_date = kwargs.get('foc_date', None)


class PhoneNumberRelease(msrest.serialization.Model):
    """Represents a release.

    :param release_id: The id of the release.
    :type release_id: str
    :param created_at: The creation time of the release.
    :type created_at: ~datetime.datetime
    :param status: The release status. Possible values include: "Pending", "InProgress",
     "Complete", "Failed", "Expired".
    :type status: str or ~azure.communication.administration.models.ReleaseStatus
    :param error_message: The underlying error message of a release.
    :type error_message: str
    :param phone_number_release_status_details: The list of phone numbers in the release, mapped to
     its individual statuses.
    :type phone_number_release_status_details: dict[str,
     ~azure.communication.administration.models.PhoneNumberReleaseDetails]
    """

    _attribute_map = {
        'release_id': {'key': 'releaseId', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'status': {'key': 'status', 'type': 'str'},
        'error_message': {'key': 'errorMessage', 'type': 'str'},
        'phone_number_release_status_details': {'key': 'phoneNumberReleaseStatusDetails', 'type': '{PhoneNumberReleaseDetails}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberRelease, self).__init__(**kwargs)
        self.release_id = kwargs.get('release_id', None)
        self.created_at = kwargs.get('created_at', None)
        self.status = kwargs.get('status', None)
        self.error_message = kwargs.get('error_message', None)
        self.phone_number_release_status_details = kwargs.get('phone_number_release_status_details', None)


class PhoneNumberReleaseDetails(msrest.serialization.Model):
    """PhoneNumberReleaseDetails.

    :param status: The release status of a phone number. Possible values include: "Pending",
     "Success", "Error", "InProgress".
    :type status: str or ~azure.communication.administration.models.PhoneNumberReleaseStatus
    :param error_code: The error code in the case the status is error.
    :type error_code: int
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'error_code': {'key': 'errorCode', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberReleaseDetails, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.error_code = kwargs.get('error_code', None)


class PhoneNumberReservation(msrest.serialization.Model):
    """Represents a phone number search.

    :param reservation_id: The id of the search.
    :type reservation_id: str
    :param display_name: The name of the search.
    :type display_name: str
    :param created_at: The creation time of the search.
    :type created_at: ~datetime.datetime
    :param description: The description of the search.
    :type description: str
    :param phone_plan_ids: The phone plan ids of the search.
    :type phone_plan_ids: list[str]
    :param area_code: The area code of the search.
    :type area_code: str
    :param quantity: The quantity of phone numbers in the search.
    :type quantity: int
    :param location_options: The location options of the search.
    :type location_options: list[~azure.communication.administration.models.LocationOptionsDetails]
    :param status: The status of the search. Possible values include: "Pending", "InProgress",
     "Reserved", "Expired", "Expiring", "Completing", "Refreshing", "Success", "Manual",
     "Cancelled", "Cancelling", "Error", "PurchasePending".
    :type status: str or ~azure.communication.administration.models.SearchStatus
    :param phone_numbers: The list of phone numbers in the search, in the case the status is
     reserved or success.
    :type phone_numbers: list[str]
    :param reservation_expiry_date: The date that search expires and the numbers become available.
    :type reservation_expiry_date: ~datetime.datetime
    :param error_code: The error code of the search.
    :type error_code: int
    """

    _attribute_map = {
        'reservation_id': {'key': 'searchId', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'description': {'key': 'description', 'type': 'str'},
        'phone_plan_ids': {'key': 'phonePlanIds', 'type': '[str]'},
        'area_code': {'key': 'areaCode', 'type': 'str'},
        'quantity': {'key': 'quantity', 'type': 'int'},
        'location_options': {'key': 'locationOptions', 'type': '[LocationOptionsDetails]'},
        'status': {'key': 'status', 'type': 'str'},
        'phone_numbers': {'key': 'phoneNumbers', 'type': '[str]'},
        'reservation_expiry_date': {'key': 'reservationExpiryDate', 'type': 'iso-8601'},
        'error_code': {'key': 'errorCode', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhoneNumberReservation, self).__init__(**kwargs)
        self.reservation_id = kwargs.get('reservation_id', None)
        self.display_name = kwargs.get('display_name', None)
        self.created_at = kwargs.get('created_at', None)
        self.description = kwargs.get('description', None)
        self.phone_plan_ids = kwargs.get('phone_plan_ids', None)
        self.area_code = kwargs.get('area_code', None)
        self.quantity = kwargs.get('quantity', None)
        self.location_options = kwargs.get('location_options', None)
        self.status = kwargs.get('status', None)
        self.phone_numbers = kwargs.get('phone_numbers', None)
        self.reservation_expiry_date = kwargs.get('reservation_expiry_date', None)
        self.error_code = kwargs.get('error_code', None)


class PhonePlan(msrest.serialization.Model):
    """Represents a phone plan.

    All required parameters must be populated in order to send to Azure.

    :param phone_plan_id: Required. The phone plan id.
    :type phone_plan_id: str
    :param localized_name: Required. The name of the phone plan.
    :type localized_name: str
    :param location_type: Required. The location type of the phone plan. Possible values include:
     "CivicAddress", "NotRequired", "Selection".
    :type location_type: str or ~azure.communication.administration.models.LocationType
    :param area_codes: The list of available area codes in the phone plan.
    :type area_codes: list[str]
    :param capabilities: Capabilities of the phone plan.
    :type capabilities: list[str or ~azure.communication.administration.models.Capability]
    :param maximum_search_size: The maximum number of phone numbers one can acquire in a search in
     this phone plan.
    :type maximum_search_size: int
    """

    _validation = {
        'phone_plan_id': {'required': True},
        'localized_name': {'required': True},
        'location_type': {'required': True},
    }

    _attribute_map = {
        'phone_plan_id': {'key': 'phonePlanId', 'type': 'str'},
        'localized_name': {'key': 'localizedName', 'type': 'str'},
        'location_type': {'key': 'locationType', 'type': 'str'},
        'area_codes': {'key': 'areaCodes', 'type': '[str]'},
        'capabilities': {'key': 'capabilities', 'type': '[str]'},
        'maximum_search_size': {'key': 'maximumSearchSize', 'type': 'int'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhonePlan, self).__init__(**kwargs)
        self.phone_plan_id = kwargs['phone_plan_id']
        self.localized_name = kwargs['localized_name']
        self.location_type = kwargs['location_type']
        self.area_codes = kwargs.get('area_codes', None)
        self.capabilities = kwargs.get('capabilities', None)
        self.maximum_search_size = kwargs.get('maximum_search_size', None)


class PhonePlanGroup(msrest.serialization.Model):
    """Represents a plan group.

    All required parameters must be populated in order to send to Azure.

    :param phone_plan_group_id: Required. The id of the plan group.
    :type phone_plan_group_id: str
    :param phone_number_type: The phone number type of the plan group. Possible values include:
     "Unknown", "Geographic", "TollFree", "Indirect".
    :type phone_number_type: str or ~azure.communication.administration.models.PhoneNumberType
    :param localized_name: Required. The name of the plan group.
    :type localized_name: str
    :param localized_description: Required. The description of the plan group.
    :type localized_description: str
    :param carrier_details: Represents carrier details.
    :type carrier_details: ~azure.communication.administration.models.CarrierDetails
    :param rate_information: Represents a wrapper of rate information.
    :type rate_information: ~azure.communication.administration.models.RateInformation
    """

    _validation = {
        'phone_plan_group_id': {'required': True},
        'localized_name': {'required': True},
        'localized_description': {'required': True},
    }

    _attribute_map = {
        'phone_plan_group_id': {'key': 'phonePlanGroupId', 'type': 'str'},
        'phone_number_type': {'key': 'phoneNumberType', 'type': 'str'},
        'localized_name': {'key': 'localizedName', 'type': 'str'},
        'localized_description': {'key': 'localizedDescription', 'type': 'str'},
        'carrier_details': {'key': 'carrierDetails', 'type': 'CarrierDetails'},
        'rate_information': {'key': 'rateInformation', 'type': 'RateInformation'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhonePlanGroup, self).__init__(**kwargs)
        self.phone_plan_group_id = kwargs['phone_plan_group_id']
        self.phone_number_type = kwargs.get('phone_number_type', None)
        self.localized_name = kwargs['localized_name']
        self.localized_description = kwargs['localized_description']
        self.carrier_details = kwargs.get('carrier_details', None)
        self.rate_information = kwargs.get('rate_information', None)


class PhonePlanGroups(msrest.serialization.Model):
    """Represents a wrapper of list of plan groups.

    :param phone_plan_groups: The underlying list of phone plan groups.
    :type phone_plan_groups: list[~azure.communication.administration.models.PhonePlanGroup]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'phone_plan_groups': {'key': 'phonePlanGroups', 'type': '[PhonePlanGroup]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhonePlanGroups, self).__init__(**kwargs)
        self.phone_plan_groups = kwargs.get('phone_plan_groups', None)
        self.next_link = kwargs.get('next_link', None)


class PhonePlansResponse(msrest.serialization.Model):
    """Represents a wrapper around a list of countries.

    :param phone_plans: Represents the underlying list of phone plans.
    :type phone_plans: list[~azure.communication.administration.models.PhonePlan]
    :param next_link: Represents the URL link to the next page.
    :type next_link: str
    """

    _attribute_map = {
        'phone_plans': {'key': 'phonePlans', 'type': '[PhonePlan]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PhonePlansResponse, self).__init__(**kwargs)
        self.phone_plans = kwargs.get('phone_plans', None)
        self.next_link = kwargs.get('next_link', None)


class PstnConfiguration(msrest.serialization.Model):
    """Definition for pstn number configuration.

    All required parameters must be populated in order to send to Azure.

    :param callback_url: Required. The webhook URL on the phone number configuration.
    :type callback_url: str
    :param application_id: The application id of the application to which to configure.
    :type application_id: str
    """

    _validation = {
        'callback_url': {'required': True},
    }

    _attribute_map = {
        'callback_url': {'key': 'callbackUrl', 'type': 'str'},
        'application_id': {'key': 'applicationId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PstnConfiguration, self).__init__(**kwargs)
        self.callback_url = kwargs['callback_url']
        self.application_id = kwargs.get('application_id', None)


class RateInformation(msrest.serialization.Model):
    """Represents a wrapper of rate information.

    :param monthly_rate: The monthly rate of a phone plan group.
    :type monthly_rate: float
    :param currency_type: The currency of a phone plan group. Possible values include: "USD".
    :type currency_type: str or ~azure.communication.administration.models.CurrencyType
    :param rate_error_message: The error code of a phone plan group.
    :type rate_error_message: str
    """

    _attribute_map = {
        'monthly_rate': {'key': 'monthlyRate', 'type': 'float'},
        'currency_type': {'key': 'currencyType', 'type': 'str'},
        'rate_error_message': {'key': 'rateErrorMessage', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RateInformation, self).__init__(**kwargs)
        self.monthly_rate = kwargs.get('monthly_rate', None)
        self.currency_type = kwargs.get('currency_type', None)
        self.rate_error_message = kwargs.get('rate_error_message', None)


class ReleaseRequest(msrest.serialization.Model):
    """Represents a release request.

    All required parameters must be populated in order to send to Azure.

    :param phone_numbers: Required. The list of phone numbers in the release request.
    :type phone_numbers: list[str]
    """

    _validation = {
        'phone_numbers': {'required': True},
    }

    _attribute_map = {
        'phone_numbers': {'key': 'phoneNumbers', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ReleaseRequest, self).__init__(**kwargs)
        self.phone_numbers = kwargs['phone_numbers']


class ReleaseResponse(msrest.serialization.Model):
    """Represents a release response.

    All required parameters must be populated in order to send to Azure.

    :param release_id: Required. The release id of a created release.
    :type release_id: str
    """

    _validation = {
        'release_id': {'required': True},
    }

    _attribute_map = {
        'release_id': {'key': 'releaseId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ReleaseResponse, self).__init__(**kwargs)
        self.release_id = kwargs['release_id']


class UpdateNumberCapabilitiesRequest(msrest.serialization.Model):
    """Represents a numbers capabilities update request.

    All required parameters must be populated in order to send to Azure.

    :param phone_number_capabilities_update: Required. The map of phone numbers to the capabilities
     update applied to the phone number.
    :type phone_number_capabilities_update: dict[str,
     ~azure.communication.administration.models.NumberUpdateCapabilities]
    """

    _validation = {
        'phone_number_capabilities_update': {'required': True},
    }

    _attribute_map = {
        'phone_number_capabilities_update': {'key': 'phoneNumberCapabilitiesUpdate', 'type': '{NumberUpdateCapabilities}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(UpdateNumberCapabilitiesRequest, self).__init__(**kwargs)
        self.phone_number_capabilities_update = kwargs['phone_number_capabilities_update']


class UpdateNumberCapabilitiesResponse(msrest.serialization.Model):
    """Represents a number capability update response.

    All required parameters must be populated in order to send to Azure.

    :param capabilities_update_id: Required. The capabilities id.
    :type capabilities_update_id: str
    """

    _validation = {
        'capabilities_update_id': {'required': True},
    }

    _attribute_map = {
        'capabilities_update_id': {'key': 'capabilitiesUpdateId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(UpdateNumberCapabilitiesResponse, self).__init__(**kwargs)
        self.capabilities_update_id = kwargs['capabilities_update_id']


class UpdatePhoneNumberCapabilitiesResponse(msrest.serialization.Model):
    """Response for getting a phone number update capabilities.

    :param capabilities_update_id: The id of the phone number capabilities update.
    :type capabilities_update_id: str
    :param created_at: The time the capabilities update was created.
    :type created_at: ~datetime.datetime
    :param capabilities_update_status: Status of the capabilities update. Possible values include:
     "Pending", "InProgress", "Complete", "Error".
    :type capabilities_update_status: str or
     ~azure.communication.administration.models.CapabilitiesUpdateStatus
    :param phone_number_capabilities_updates: The capabilities update for each of a set of phone
     numbers.
    :type phone_number_capabilities_updates: dict[str,
     ~azure.communication.administration.models.NumberUpdateCapabilities]
    """

    _attribute_map = {
        'capabilities_update_id': {'key': 'capabilitiesUpdateId', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'capabilities_update_status': {'key': 'capabilitiesUpdateStatus', 'type': 'str'},
        'phone_number_capabilities_updates': {'key': 'phoneNumberCapabilitiesUpdates', 'type': '{NumberUpdateCapabilities}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(UpdatePhoneNumberCapabilitiesResponse, self).__init__(**kwargs)
        self.capabilities_update_id = kwargs.get('capabilities_update_id', None)
        self.created_at = kwargs.get('created_at', None)
        self.capabilities_update_status = kwargs.get('capabilities_update_status', None)
        self.phone_number_capabilities_updates = kwargs.get('phone_number_capabilities_updates', None)
