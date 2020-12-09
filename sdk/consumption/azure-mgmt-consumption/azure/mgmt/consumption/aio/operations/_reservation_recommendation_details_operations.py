# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class ReservationRecommendationDetailsOperations:
    """ReservationRecommendationDetailsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.consumption.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def get(
        self,
        billing_scope: str,
        scope: Union[str, "models.Scope"],
        region: str,
        term: Union[str, "models.Term"],
        look_back_period: Union[str, "models.LookBackPeriod"],
        product: str,
        **kwargs
    ) -> Optional["models.ReservationRecommendationDetailsModel"]:
        """Details of a reservation recommendation for what-if analysis of reserved instances.

        :param billing_scope: The scope associated with reservation recommendation details operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription scope,
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' for resource group scope,
         /providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for BillingAccount scope, and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for billingProfile scope.
        :type billing_scope: str
        :param scope: Scope of the reservation.
        :type scope: str or ~azure.mgmt.consumption.models.Scope
        :param region: Used to select the region the recommendation should be generated for.
        :type region: str
        :param term: Specify length of reservation recommendation term.
        :type term: str or ~azure.mgmt.consumption.models.Term
        :param look_back_period: Filter the time period on which reservation recommendation results are
         based.
        :type look_back_period: str or ~azure.mgmt.consumption.models.LookBackPeriod
        :param product: Filter the products for which reservation recommendation results are generated.
         Examples: Standard_DS1_v2 (for VM), Premium_SSD_Managed_Disks_P30 (for Managed Disks).
        :type product: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ReservationRecommendationDetailsModel, or the result of cls(response)
        :rtype: ~azure.mgmt.consumption.models.ReservationRecommendationDetailsModel or None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[Optional["models.ReservationRecommendationDetailsModel"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingScope': self._serialize.url("billing_scope", billing_scope, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        query_parameters['scope'] = self._serialize.query("scope", scope, 'str')
        query_parameters['region'] = self._serialize.query("region", region, 'str')
        query_parameters['term'] = self._serialize.query("term", term, 'str')
        query_parameters['lookBackPeriod'] = self._serialize.query("look_back_period", look_back_period, 'str')
        query_parameters['product'] = self._serialize.query("product", product, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('ReservationRecommendationDetailsModel', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/{billingScope}/providers/Microsoft.Consumption/reservationRecommendationDetails'}  # type: ignore
