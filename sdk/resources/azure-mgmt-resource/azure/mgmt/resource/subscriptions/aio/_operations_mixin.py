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
from msrest import Serializer, Deserializer
from typing import Any, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat


class SubscriptionClientOperationsMixin(object):

    async def check_resource_name(
        self,
        resource_name_definition: Optional["_models.ResourceName"] = None,
        **kwargs: Any
    ) -> "_models.CheckResourceNameResult":
        """Checks resource name validity.

        A resource name is valid if it is not a reserved word, does not contains a reserved word and
        does not start with a reserved word.

        :param resource_name_definition: Resource object with values for resource name and resource
         type.
        :type resource_name_definition: ~azure.mgmt.resource.subscriptions.v2019_11_01.models.ResourceName
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CheckResourceNameResult, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.subscriptions.v2019_11_01.models.CheckResourceNameResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('check_resource_name')
        if api_version == '2016-06-01':
            from ..v2016_06_01.aio.operations import SubscriptionClientOperationsMixin as OperationClass
        elif api_version == '2018-06-01':
            from ..v2018_06_01.aio.operations import SubscriptionClientOperationsMixin as OperationClass
        elif api_version == '2019-06-01':
            from ..v2019_06_01.aio.operations import SubscriptionClientOperationsMixin as OperationClass
        elif api_version == '2019-11-01':
            from ..v2019_11_01.aio.operations import SubscriptionClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'check_resource_name'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._serialize.client_side_validation = False
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.check_resource_name(resource_name_definition, **kwargs)
