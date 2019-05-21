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
    from .image_template_source_py3 import ImageTemplateSource
    from .image_template_customizer_py3 import ImageTemplateCustomizer
    from .image_template_distributor_py3 import ImageTemplateDistributor
    from .provisioning_error_py3 import ProvisioningError
    from .image_template_last_run_status_py3 import ImageTemplateLastRunStatus
    from .image_template_identity_user_assigned_identities_value_py3 import ImageTemplateIdentityUserAssignedIdentitiesValue
    from .image_template_identity_py3 import ImageTemplateIdentity
    from .image_template_py3 import ImageTemplate
    from .image_template_iso_source_py3 import ImageTemplateIsoSource
    from .image_template_platform_image_source_py3 import ImageTemplatePlatformImageSource
    from .image_template_managed_image_source_py3 import ImageTemplateManagedImageSource
    from .image_template_shared_image_version_source_py3 import ImageTemplateSharedImageVersionSource
    from .image_template_shell_customizer_py3 import ImageTemplateShellCustomizer
    from .image_template_restart_customizer_py3 import ImageTemplateRestartCustomizer
    from .image_template_power_shell_customizer_py3 import ImageTemplatePowerShellCustomizer
    from .image_template_file_customizer_py3 import ImageTemplateFileCustomizer
    from .image_template_managed_image_distributor_py3 import ImageTemplateManagedImageDistributor
    from .image_template_shared_image_distributor_py3 import ImageTemplateSharedImageDistributor
    from .image_template_vhd_distributor_py3 import ImageTemplateVhdDistributor
    from .image_template_update_parameters_py3 import ImageTemplateUpdateParameters
    from .run_output_py3 import RunOutput
    from .resource_py3 import Resource
    from .sub_resource_py3 import SubResource
    from .operation_display_py3 import OperationDisplay
    from .operation_py3 import Operation
    from .api_error_base_py3 import ApiErrorBase
    from .inner_error_py3 import InnerError
    from .api_error_py3 import ApiError, ApiErrorException
except (SyntaxError, ImportError):
    from .image_template_source import ImageTemplateSource
    from .image_template_customizer import ImageTemplateCustomizer
    from .image_template_distributor import ImageTemplateDistributor
    from .provisioning_error import ProvisioningError
    from .image_template_last_run_status import ImageTemplateLastRunStatus
    from .image_template_identity_user_assigned_identities_value import ImageTemplateIdentityUserAssignedIdentitiesValue
    from .image_template_identity import ImageTemplateIdentity
    from .image_template import ImageTemplate
    from .image_template_iso_source import ImageTemplateIsoSource
    from .image_template_platform_image_source import ImageTemplatePlatformImageSource
    from .image_template_managed_image_source import ImageTemplateManagedImageSource
    from .image_template_shared_image_version_source import ImageTemplateSharedImageVersionSource
    from .image_template_shell_customizer import ImageTemplateShellCustomizer
    from .image_template_restart_customizer import ImageTemplateRestartCustomizer
    from .image_template_power_shell_customizer import ImageTemplatePowerShellCustomizer
    from .image_template_file_customizer import ImageTemplateFileCustomizer
    from .image_template_managed_image_distributor import ImageTemplateManagedImageDistributor
    from .image_template_shared_image_distributor import ImageTemplateSharedImageDistributor
    from .image_template_vhd_distributor import ImageTemplateVhdDistributor
    from .image_template_update_parameters import ImageTemplateUpdateParameters
    from .run_output import RunOutput
    from .resource import Resource
    from .sub_resource import SubResource
    from .operation_display import OperationDisplay
    from .operation import Operation
    from .api_error_base import ApiErrorBase
    from .inner_error import InnerError
    from .api_error import ApiError, ApiErrorException
from .image_template_paged import ImageTemplatePaged
from .run_output_paged import RunOutputPaged
from .operation_paged import OperationPaged
from .image_builder_client_enums import (
    ResourceIdentityType,
)

__all__ = [
    'ImageTemplateSource',
    'ImageTemplateCustomizer',
    'ImageTemplateDistributor',
    'ProvisioningError',
    'ImageTemplateLastRunStatus',
    'ImageTemplateIdentityUserAssignedIdentitiesValue',
    'ImageTemplateIdentity',
    'ImageTemplate',
    'ImageTemplateIsoSource',
    'ImageTemplatePlatformImageSource',
    'ImageTemplateManagedImageSource',
    'ImageTemplateSharedImageVersionSource',
    'ImageTemplateShellCustomizer',
    'ImageTemplateRestartCustomizer',
    'ImageTemplatePowerShellCustomizer',
    'ImageTemplateFileCustomizer',
    'ImageTemplateManagedImageDistributor',
    'ImageTemplateSharedImageDistributor',
    'ImageTemplateVhdDistributor',
    'ImageTemplateUpdateParameters',
    'RunOutput',
    'Resource',
    'SubResource',
    'OperationDisplay',
    'Operation',
    'ApiErrorBase',
    'InnerError',
    'ApiError', 'ApiErrorException',
    'ImageTemplatePaged',
    'RunOutputPaged',
    'OperationPaged',
    'ResourceIdentityType',
]
