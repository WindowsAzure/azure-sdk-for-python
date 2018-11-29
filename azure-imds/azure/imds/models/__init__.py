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

try:
    from .plan_properties_py3 import PlanProperties
    from .public_keys_properties_py3 import PublicKeysProperties
    from .compute_py3 import Compute
    from .ipv4_properties_py3 import Ipv4Properties
    from .subnet_properties_py3 import SubnetProperties
    from .network_interface_ipv4_py3 import NetworkInterfaceIpv4
    from .ipv6_properties_py3 import Ipv6Properties
    from .network_interface_ipv6_py3 import NetworkInterfaceIpv6
    from .network_interface_py3 import NetworkInterface
    from .network_py3 import Network
    from .instance_py3 import Instance
    from .attested_py3 import Attested
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .identity_error_response_py3 import IdentityErrorResponse, IdentityErrorResponseException
    from .identity_token_response_py3 import IdentityTokenResponse
    from .identity_info_response_py3 import IdentityInfoResponse
except (SyntaxError, ImportError):
    from .plan_properties import PlanProperties
    from .public_keys_properties import PublicKeysProperties
    from .compute import Compute
    from .ipv4_properties import Ipv4Properties
    from .subnet_properties import SubnetProperties
    from .network_interface_ipv4 import NetworkInterfaceIpv4
    from .ipv6_properties import Ipv6Properties
    from .network_interface_ipv6 import NetworkInterfaceIpv6
    from .network_interface import NetworkInterface
    from .network import Network
    from .instance import Instance
    from .attested import Attested
    from .error_response import ErrorResponse, ErrorResponseException
    from .identity_error_response import IdentityErrorResponse, IdentityErrorResponseException
    from .identity_token_response import IdentityTokenResponse
    from .identity_info_response import IdentityInfoResponse
from .instance_metadata_client_enums import (
    Error,
    ApiVersion,
    BypassCache,
)

__all__ = [
    'PlanProperties',
    'PublicKeysProperties',
    'Compute',
    'Ipv4Properties',
    'SubnetProperties',
    'NetworkInterfaceIpv4',
    'Ipv6Properties',
    'NetworkInterfaceIpv6',
    'NetworkInterface',
    'Network',
    'Instance',
    'Attested',
    'ErrorResponse', 'ErrorResponseException',
    'IdentityErrorResponse', 'IdentityErrorResponseException',
    'IdentityTokenResponse',
    'IdentityInfoResponse',
    'Error',
    'ApiVersion',
    'BypassCache',
]
