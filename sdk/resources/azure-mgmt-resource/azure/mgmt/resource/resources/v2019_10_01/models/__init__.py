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
    from ._models_py3 import Alias
    from ._models_py3 import AliasPath
    from ._models_py3 import AliasPattern
    from ._models_py3 import BasicDependency
    from ._models_py3 import DebugSetting
    from ._models_py3 import Dependency
    from ._models_py3 import Deployment
    from ._models_py3 import DeploymentExportResult
    from ._models_py3 import DeploymentExtended
    from ._models_py3 import DeploymentExtendedFilter
    from ._models_py3 import DeploymentOperation
    from ._models_py3 import DeploymentOperationProperties
    from ._models_py3 import DeploymentProperties
    from ._models_py3 import DeploymentPropertiesExtended
    from ._models_py3 import DeploymentValidateResult
    from ._models_py3 import DeploymentWhatIf
    from ._models_py3 import DeploymentWhatIfProperties
    from ._models_py3 import DeploymentWhatIfSettings
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorResponse
    from ._models_py3 import ExportTemplateRequest
    from ._models_py3 import GenericResource
    from ._models_py3 import GenericResourceExpanded
    from ._models_py3 import GenericResourceFilter
    from ._models_py3 import HttpMessage
    from ._models_py3 import Identity
    from ._models_py3 import IdentityUserAssignedIdentitiesValue
    from ._models_py3 import OnErrorDeployment
    from ._models_py3 import OnErrorDeploymentExtended
    from ._models_py3 import Operation
    from ._models_py3 import OperationDisplay
    from ._models_py3 import ParametersLink
    from ._models_py3 import Plan
    from ._models_py3 import Provider
    from ._models_py3 import ProviderResourceType
    from ._models_py3 import Resource
    from ._models_py3 import ResourceGroup
    from ._models_py3 import ResourceGroupExportResult
    from ._models_py3 import ResourceGroupFilter
    from ._models_py3 import ResourceGroupPatchable
    from ._models_py3 import ResourceGroupProperties
    from ._models_py3 import ResourceProviderOperationDisplayProperties
    from ._models_py3 import ResourceReference
    from ._models_py3 import ResourcesMoveInfo
    from ._models_py3 import ScopedDeployment
    from ._models_py3 import ScopedDeploymentWhatIf
    from ._models_py3 import Sku
    from ._models_py3 import SubResource
    from ._models_py3 import TagCount
    from ._models_py3 import TagDetails
    from ._models_py3 import Tags
    from ._models_py3 import TagsPatchResource
    from ._models_py3 import TagsResource
    from ._models_py3 import TagValue
    from ._models_py3 import TargetResource
    from ._models_py3 import TemplateHashResult
    from ._models_py3 import TemplateLink
    from ._models_py3 import WhatIfChange
    from ._models_py3 import WhatIfOperationResult
    from ._models_py3 import WhatIfPropertyChange
    from ._models_py3 import ZoneMapping
except (SyntaxError, ImportError):
    from ._models import Alias
    from ._models import AliasPath
    from ._models import AliasPattern
    from ._models import BasicDependency
    from ._models import DebugSetting
    from ._models import Dependency
    from ._models import Deployment
    from ._models import DeploymentExportResult
    from ._models import DeploymentExtended
    from ._models import DeploymentExtendedFilter
    from ._models import DeploymentOperation
    from ._models import DeploymentOperationProperties
    from ._models import DeploymentProperties
    from ._models import DeploymentPropertiesExtended
    from ._models import DeploymentValidateResult
    from ._models import DeploymentWhatIf
    from ._models import DeploymentWhatIfProperties
    from ._models import DeploymentWhatIfSettings
    from ._models import ErrorAdditionalInfo
    from ._models import ErrorResponse
    from ._models import ExportTemplateRequest
    from ._models import GenericResource
    from ._models import GenericResourceExpanded
    from ._models import GenericResourceFilter
    from ._models import HttpMessage
    from ._models import Identity
    from ._models import IdentityUserAssignedIdentitiesValue
    from ._models import OnErrorDeployment
    from ._models import OnErrorDeploymentExtended
    from ._models import Operation
    from ._models import OperationDisplay
    from ._models import ParametersLink
    from ._models import Plan
    from ._models import Provider
    from ._models import ProviderResourceType
    from ._models import Resource
    from ._models import ResourceGroup
    from ._models import ResourceGroupExportResult
    from ._models import ResourceGroupFilter
    from ._models import ResourceGroupPatchable
    from ._models import ResourceGroupProperties
    from ._models import ResourceProviderOperationDisplayProperties
    from ._models import ResourceReference
    from ._models import ResourcesMoveInfo
    from ._models import ScopedDeployment
    from ._models import ScopedDeploymentWhatIf
    from ._models import Sku
    from ._models import SubResource
    from ._models import TagCount
    from ._models import TagDetails
    from ._models import Tags
    from ._models import TagsPatchResource
    from ._models import TagsResource
    from ._models import TagValue
    from ._models import TargetResource
    from ._models import TemplateHashResult
    from ._models import TemplateLink
    from ._models import WhatIfChange
    from ._models import WhatIfOperationResult
    from ._models import WhatIfPropertyChange
    from ._models import ZoneMapping
from ._paged_models import DeploymentExtendedPaged
from ._paged_models import DeploymentOperationPaged
from ._paged_models import GenericResourceExpandedPaged
from ._paged_models import OperationPaged
from ._paged_models import ProviderPaged
from ._paged_models import ResourceGroupPaged
from ._paged_models import TagDetailsPaged
from ._resource_management_client_enums import (
    DeploymentMode,
    OnErrorDeploymentType,
    WhatIfResultFormat,
    AliasPatternType,
    AliasType,
    ResourceIdentityType,
    ProvisioningOperation,
    PropertyChangeType,
    ChangeType,
    TagsPatchOperation,
)

__all__ = [
    'Alias',
    'AliasPath',
    'AliasPattern',
    'BasicDependency',
    'DebugSetting',
    'Dependency',
    'Deployment',
    'DeploymentExportResult',
    'DeploymentExtended',
    'DeploymentExtendedFilter',
    'DeploymentOperation',
    'DeploymentOperationProperties',
    'DeploymentProperties',
    'DeploymentPropertiesExtended',
    'DeploymentValidateResult',
    'DeploymentWhatIf',
    'DeploymentWhatIfProperties',
    'DeploymentWhatIfSettings',
    'ErrorAdditionalInfo',
    'ErrorResponse',
    'ExportTemplateRequest',
    'GenericResource',
    'GenericResourceExpanded',
    'GenericResourceFilter',
    'HttpMessage',
    'Identity',
    'IdentityUserAssignedIdentitiesValue',
    'OnErrorDeployment',
    'OnErrorDeploymentExtended',
    'Operation',
    'OperationDisplay',
    'ParametersLink',
    'Plan',
    'Provider',
    'ProviderResourceType',
    'Resource',
    'ResourceGroup',
    'ResourceGroupExportResult',
    'ResourceGroupFilter',
    'ResourceGroupPatchable',
    'ResourceGroupProperties',
    'ResourceProviderOperationDisplayProperties',
    'ResourceReference',
    'ResourcesMoveInfo',
    'ScopedDeployment',
    'ScopedDeploymentWhatIf',
    'Sku',
    'SubResource',
    'TagCount',
    'TagDetails',
    'Tags',
    'TagsPatchResource',
    'TagsResource',
    'TagValue',
    'TargetResource',
    'TemplateHashResult',
    'TemplateLink',
    'WhatIfChange',
    'WhatIfOperationResult',
    'WhatIfPropertyChange',
    'ZoneMapping',
    'OperationPaged',
    'DeploymentExtendedPaged',
    'ProviderPaged',
    'GenericResourceExpandedPaged',
    'ResourceGroupPaged',
    'TagDetailsPaged',
    'DeploymentOperationPaged',
    'DeploymentMode',
    'OnErrorDeploymentType',
    'WhatIfResultFormat',
    'AliasPatternType',
    'AliasType',
    'ResourceIdentityType',
    'ProvisioningOperation',
    'PropertyChangeType',
    'ChangeType',
    'TagsPatchOperation',
]
