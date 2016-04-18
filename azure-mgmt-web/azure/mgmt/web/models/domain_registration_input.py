# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class DomainRegistrationInput(Resource):
    """
    Domain registration input for validation Api

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param domain_registration_input_name: Name of the domain
    :type domain_registration_input_name: str
    :param contact_admin: Admin contact information
    :type contact_admin: :class:`Contact
     <websitemanagementclient.models.Contact>`
    :param contact_billing: Billing contact information
    :type contact_billing: :class:`Contact
     <websitemanagementclient.models.Contact>`
    :param contact_registrant: Registrant contact information
    :type contact_registrant: :class:`Contact
     <websitemanagementclient.models.Contact>`
    :param contact_tech: Technical contact information
    :type contact_tech: :class:`Contact
     <websitemanagementclient.models.Contact>`
    :param registration_status: Domain registration status. Possible values
     include: 'Active', 'Awaiting', 'Cancelled', 'Confiscated', 'Disabled',
     'Excluded', 'Expired', 'Failed', 'Held', 'Locked', 'Parked', 'Pending',
     'Reserved', 'Reverted', 'Suspended', 'Transferred', 'Unknown',
     'Unlocked', 'Unparked', 'Updated', 'JsonConverterFailed'
    :type registration_status: str
    :param provisioning_state: Domain provisioning state. Possible values
     include: 'Succeeded', 'Failed', 'Canceled', 'InProgress', 'Deleting'
    :type provisioning_state: str
    :param name_servers: Name servers
    :type name_servers: list of str
    :param privacy: If true then domain privacy is enabled for this domain
    :type privacy: bool
    :param created_time: Domain creation timestamp
    :type created_time: datetime
    :param expiration_time: Domain expiration timestamp
    :type expiration_time: datetime
    :param last_renewed_time: Timestamp when the domain was renewed last time
    :type last_renewed_time: datetime
    :param auto_renew: If true then domain will renewed automatically
    :type auto_renew: bool
    :param ready_for_dns_record_management: If true then Azure can assign
     this domain to Web Apps. This value will be true if domain registration
     status is active and it is hosted on name servers Azure has programmatic
     access to
    :type ready_for_dns_record_management: bool
    :param managed_host_names: All hostnames derived from the domain and
     assigned to Azure resources
    :type managed_host_names: list of :class:`HostName
     <websitemanagementclient.models.HostName>`
    :param consent: Legal agreement consent
    :type consent: :class:`DomainPurchaseConsent
     <websitemanagementclient.models.DomainPurchaseConsent>`
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'domain_registration_input_name': {'key': 'properties.name', 'type': 'str'},
        'contact_admin': {'key': 'properties.contactAdmin', 'type': 'Contact'},
        'contact_billing': {'key': 'properties.contactBilling', 'type': 'Contact'},
        'contact_registrant': {'key': 'properties.contactRegistrant', 'type': 'Contact'},
        'contact_tech': {'key': 'properties.contactTech', 'type': 'Contact'},
        'registration_status': {'key': 'properties.registrationStatus', 'type': 'DomainStatus'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningState'},
        'name_servers': {'key': 'properties.nameServers', 'type': '[str]'},
        'privacy': {'key': 'properties.privacy', 'type': 'bool'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'expiration_time': {'key': 'properties.expirationTime', 'type': 'iso-8601'},
        'last_renewed_time': {'key': 'properties.lastRenewedTime', 'type': 'iso-8601'},
        'auto_renew': {'key': 'properties.autoRenew', 'type': 'bool'},
        'ready_for_dns_record_management': {'key': 'properties.readyForDnsRecordManagement', 'type': 'bool'},
        'managed_host_names': {'key': 'properties.managedHostNames', 'type': '[HostName]'},
        'consent': {'key': 'properties.consent', 'type': 'DomainPurchaseConsent'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, domain_registration_input_name=None, contact_admin=None, contact_billing=None, contact_registrant=None, contact_tech=None, registration_status=None, provisioning_state=None, name_servers=None, privacy=None, created_time=None, expiration_time=None, last_renewed_time=None, auto_renew=None, ready_for_dns_record_management=None, managed_host_names=None, consent=None):
        super(DomainRegistrationInput, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.domain_registration_input_name = domain_registration_input_name
        self.contact_admin = contact_admin
        self.contact_billing = contact_billing
        self.contact_registrant = contact_registrant
        self.contact_tech = contact_tech
        self.registration_status = registration_status
        self.provisioning_state = provisioning_state
        self.name_servers = name_servers
        self.privacy = privacy
        self.created_time = created_time
        self.expiration_time = expiration_time
        self.last_renewed_time = last_renewed_time
        self.auto_renew = auto_renew
        self.ready_for_dns_record_management = ready_for_dns_record_management
        self.managed_host_names = managed_host_names
        self.consent = consent
