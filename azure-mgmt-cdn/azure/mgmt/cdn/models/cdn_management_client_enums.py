# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from enum import Enum


class SkuName(Enum):

    standard = "Standard"
    premium = "Premium"


class ProfileResourceState(Enum):

    creating = "Creating"
    active = "Active"
    deleting = "Deleting"
    disabled = "Disabled"


class ProvisioningState(Enum):

    creating = "Creating"
    succeeded = "Succeeded"
    failed = "Failed"


class QueryStringCachingBehavior(Enum):

    ignore_query_string = "IgnoreQueryString"
    bypass_caching = "BypassCaching"
    use_query_string = "UseQueryString"
    not_set = "NotSet"


class EndpointResourceState(Enum):

    creating = "Creating"
    deleting = "Deleting"
    running = "Running"
    starting = "Starting"
    stopped = "Stopped"
    stopping = "Stopping"


class OriginResourceState(Enum):

    creating = "Creating"
    active = "Active"
    deleting = "Deleting"


class CustomDomainResourceState(Enum):

    creating = "Creating"
    active = "Active"
    deleting = "Deleting"


class ResourceType(Enum):

    microsoft_cdn_profiles_endpoints = "Microsoft.Cdn/Profiles/Endpoints"
