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
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar, Union


class WebSiteManagementClientOperationsMixin(object):

    def check_name_availability(
        self,
        name,  # type: str
        type,  # type: Union[str, "_models.CheckNameResourceTypes"]
        is_fqdn=None,  # type: Optional[bool]
        **kwargs  # type: Any
    ):
        """Check if a resource name is available.

        Description for Check if a resource name is available.

        :param name: Resource name to verify.
        :type name: str
        :param type: Resource type used for verification.
        :type type: str or ~azure.mgmt.web.v2020_09_01.models.CheckNameResourceTypes
        :param is_fqdn: Is fully qualified domain name.
        :type is_fqdn: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceNameAvailability, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.ResourceNameAvailability
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('check_name_availability')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'check_name_availability'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.check_name_availability(name, type, is_fqdn, **kwargs)

    def generate_github_access_token_for_appservice_cli_async(
        self,
        code,  # type: str
        state,  # type: str
        **kwargs  # type: Any
    ):
        """Exchange code for GitHub access token for AppService CLI.

        Description for Exchange code for GitHub access token for AppService CLI.

        :param code: Code string to exchange for Github Access token.
        :type code: str
        :param state: State string used for verification.
        :type state: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AppserviceGithubToken, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.AppserviceGithubToken
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('generate_github_access_token_for_appservice_cli_async')
        if api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'generate_github_access_token_for_appservice_cli_async'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.generate_github_access_token_for_appservice_cli_async(code, state, **kwargs)

    def get_publishing_user(
        self,
        **kwargs  # type: Any
    ):
        """Gets publishing user.

        Description for Gets publishing user.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: User, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.User
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('get_publishing_user')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'get_publishing_user'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.get_publishing_user(**kwargs)

    def get_source_control(
        self,
        source_control_type,  # type: str
        **kwargs  # type: Any
    ):
        """Gets source control token.

        Description for Gets source control token.

        :param source_control_type: Type of source control.
        :type source_control_type: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SourceControl, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.SourceControl
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('get_source_control')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'get_source_control'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.get_source_control(source_control_type, **kwargs)

    def get_subscription_deployment_locations(
        self,
        **kwargs  # type: Any
    ):
        """Gets list of available geo regions plus ministamps.

        Description for Gets list of available geo regions plus ministamps.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentLocations, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.DeploymentLocations
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('get_subscription_deployment_locations')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'get_subscription_deployment_locations'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.get_subscription_deployment_locations(**kwargs)

    def list_billing_meters(
        self,
        billing_location=None,  # type: Optional[str]
        os_type=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        """Gets a list of meters for a given location.

        Description for Gets a list of meters for a given location.

        :param billing_location: Azure Location of billable resource.
        :type billing_location: str
        :param os_type: App Service OS type meters used for.
        :type os_type: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BillingMeterCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2020_09_01.models.BillingMeterCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_billing_meters')
        if api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_billing_meters'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_billing_meters(billing_location, os_type, **kwargs)

    def list_geo_regions(
        self,
        sku=None,  # type: Optional[Union[str, "_models.SkuName"]]
        linux_workers_enabled=None,  # type: Optional[bool]
        xenon_workers_enabled=None,  # type: Optional[bool]
        linux_dynamic_workers_enabled=None,  # type: Optional[bool]
        **kwargs  # type: Any
    ):
        """Get a list of available geographical regions.

        Description for Get a list of available geographical regions.

        :param sku: Name of SKU used to filter the regions.
        :type sku: str or ~azure.mgmt.web.v2020_09_01.models.SkuName
        :param linux_workers_enabled: Specify :code:`<code>true</code>` if you want to filter to only
         regions that support Linux workers.
        :type linux_workers_enabled: bool
        :param xenon_workers_enabled: Specify :code:`<code>true</code>` if you want to filter to only
         regions that support Xenon workers.
        :type xenon_workers_enabled: bool
        :param linux_dynamic_workers_enabled: Specify :code:`<code>true</code>` if you want to filter
         to only regions that support Linux Consumption Workers.
        :type linux_dynamic_workers_enabled: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either GeoRegionCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2020_09_01.models.GeoRegionCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_geo_regions')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_geo_regions'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_geo_regions(sku, linux_workers_enabled, xenon_workers_enabled, linux_dynamic_workers_enabled, **kwargs)

    def list_premier_add_on_offers(
        self,
        **kwargs  # type: Any
    ):
        """List all premier add-on offers.

        Description for List all premier add-on offers.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PremierAddOnOfferCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2020_09_01.models.PremierAddOnOfferCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_premier_add_on_offers')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_premier_add_on_offers'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_premier_add_on_offers(**kwargs)

    def list_site_identifiers_assigned_to_host_name(
        self,
        name_identifier,  # type: "_models.NameIdentifier"
        **kwargs  # type: Any
    ):
        """List all apps that are assigned to a hostname.

        Description for List all apps that are assigned to a hostname.

        :param name_identifier: Hostname information.
        :type name_identifier: ~azure.mgmt.web.v2020_09_01.models.NameIdentifier
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either IdentifierCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2020_09_01.models.IdentifierCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_site_identifiers_assigned_to_host_name')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_site_identifiers_assigned_to_host_name'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_site_identifiers_assigned_to_host_name(name_identifier, **kwargs)

    def list_skus(
        self,
        **kwargs  # type: Any
    ):
        """List all SKUs.

        Description for List all SKUs.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SkuInfos, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.SkuInfos
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_skus')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_skus'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_skus(**kwargs)

    def list_source_controls(
        self,
        **kwargs  # type: Any
    ):
        """Gets the source controls available for Azure websites.

        Description for Gets the source controls available for Azure websites.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either SourceControlCollection or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.web.v2020_09_01.models.SourceControlCollection]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('list_source_controls')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'list_source_controls'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.list_source_controls(**kwargs)

    def move(
        self,
        resource_group_name,  # type: str
        move_resource_envelope,  # type: "_models.CsmMoveResourceEnvelope"
        **kwargs  # type: Any
    ):
        """Move resources between resource groups.

        Description for Move resources between resource groups.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param move_resource_envelope: Object that represents the resource to move.
        :type move_resource_envelope: ~azure.mgmt.web.v2020_09_01.models.CsmMoveResourceEnvelope
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('move')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'move'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.move(resource_group_name, move_resource_envelope, **kwargs)

    def update_publishing_user(
        self,
        user_details,  # type: "_models.User"
        **kwargs  # type: Any
    ):
        """Updates publishing user.

        Description for Updates publishing user.

        :param user_details: Details of publishing user.
        :type user_details: ~azure.mgmt.web.v2020_09_01.models.User
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: User, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.User
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('update_publishing_user')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'update_publishing_user'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.update_publishing_user(user_details, **kwargs)

    def update_source_control(
        self,
        source_control_type,  # type: str
        request_message,  # type: "_models.SourceControl"
        **kwargs  # type: Any
    ):
        """Updates source control token.

        Description for Updates source control token.

        :param source_control_type: Type of source control.
        :type source_control_type: str
        :param request_message: Source control token information.
        :type request_message: ~azure.mgmt.web.v2020_09_01.models.SourceControl
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SourceControl, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.SourceControl
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('update_source_control')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'update_source_control'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.update_source_control(source_control_type, request_message, **kwargs)

    def validate(
        self,
        resource_group_name,  # type: str
        validate_request,  # type: "_models.ValidateRequest"
        **kwargs  # type: Any
    ):
        """Validate if a resource can be created.

        Description for Validate if a resource can be created.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param validate_request: Request with the resources to validate.
        :type validate_request: ~azure.mgmt.web.v2020_09_01.models.ValidateRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ValidateResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.ValidateResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('validate')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'validate'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.validate(resource_group_name, validate_request, **kwargs)

    def validate_container_settings(
        self,
        resource_group_name,  # type: str
        validate_container_settings_request,  # type: "_models.ValidateContainerSettingsRequest"
        **kwargs  # type: Any
    ):
        """Validate if the container settings are correct.

        Validate if the container settings are correct.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param validate_container_settings_request:
        :type validate_container_settings_request: ~azure.mgmt.web.v2018_02_01.models.ValidateContainerSettingsRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: object, or the result of cls(response)
        :rtype: object
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('validate_container_settings')
        if api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'validate_container_settings'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.validate_container_settings(resource_group_name, validate_container_settings_request, **kwargs)

    def validate_move(
        self,
        resource_group_name,  # type: str
        move_resource_envelope,  # type: "_models.CsmMoveResourceEnvelope"
        **kwargs  # type: Any
    ):
        """Validate whether a resource can be moved.

        Description for Validate whether a resource can be moved.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param move_resource_envelope: Object that represents the resource to move.
        :type move_resource_envelope: ~azure.mgmt.web.v2020_09_01.models.CsmMoveResourceEnvelope
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('validate_move')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'validate_move'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.validate_move(resource_group_name, move_resource_envelope, **kwargs)

    def verify_hosting_environment_vnet(
        self,
        parameters,  # type: "_models.VnetParameters"
        **kwargs  # type: Any
    ):
        """Verifies if this VNET is compatible with an App Service Environment by analyzing the Network Security Group rules.

        Description for Verifies if this VNET is compatible with an App Service Environment by
        analyzing the Network Security Group rules.

        :param parameters: VNET information.
        :type parameters: ~azure.mgmt.web.v2020_09_01.models.VnetParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: VnetValidationFailureDetails, or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2020_09_01.models.VnetValidationFailureDetails
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('verify_hosting_environment_vnet')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2018-02-01':
            from .v2018_02_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2019-08-01':
            from .v2019_08_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-06-01':
            from .v2020_06_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        elif api_version == '2020-09-01':
            from .v2020_09_01.operations import WebSiteManagementClientOperationsMixin as OperationClass
        else:
            raise ValueError("API version {} does not have operation 'verify_hosting_environment_vnet'".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return mixin_instance.verify_hosting_environment_vnet(parameters, **kwargs)
