# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class DpsCertificateOperations:
    """DpsCertificateOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.iothubprovisioningservices.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def get(
        self,
        certificate_name: str,
        resource_group_name: str,
        provisioning_service_name: str,
        if_match: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.CertificateResponse":
        """Get the certificate from the provisioning service.

        :param certificate_name: Name of the certificate to retrieve.
        :type certificate_name: str
        :param resource_group_name: Resource group identifier.
        :type resource_group_name: str
        :param provisioning_service_name: Name of the provisioning service the certificate is
         associated with.
        :type provisioning_service_name: str
        :param if_match: ETag of the certificate.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.iothubprovisioningservices.models.CertificateResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates/{certificateName}'}  # type: ignore

    async def create_or_update(
        self,
        resource_group_name: str,
        provisioning_service_name: str,
        certificate_name: str,
        certificate_description: "_models.CertificateBodyDescription",
        if_match: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.CertificateResponse":
        """Upload the certificate to the provisioning service.

        Add new certificate or update an existing certificate.

        :param resource_group_name: Resource group identifier.
        :type resource_group_name: str
        :param provisioning_service_name: The name of the provisioning service.
        :type provisioning_service_name: str
        :param certificate_name: The name of the certificate create or update.
        :type certificate_name: str
        :param certificate_description: The certificate body.
        :type certificate_description: ~azure.mgmt.iothubprovisioningservices.models.CertificateBodyDescription
        :param if_match: ETag of the certificate. This is required to update an existing certificate,
         and ignored while creating a brand new certificate.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.iothubprovisioningservices.models.CertificateResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=256, min_length=0),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(certificate_description, 'CertificateBodyDescription')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates/{certificateName}'}  # type: ignore

    async def delete(
        self,
        resource_group_name: str,
        if_match: str,
        provisioning_service_name: str,
        certificate_name: str,
        certificate_name1: Optional[str] = None,
        certificate_raw_bytes: Optional[bytearray] = None,
        certificate_is_verified: Optional[bool] = None,
        certificate_purpose: Optional[Union[str, "_models.CertificatePurpose"]] = None,
        certificate_created: Optional[datetime.datetime] = None,
        certificate_last_updated: Optional[datetime.datetime] = None,
        certificate_has_private_key: Optional[bool] = None,
        certificate_nonce: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Delete the Provisioning Service Certificate.

        Deletes the specified certificate associated with the Provisioning Service.

        :param resource_group_name: Resource group identifier.
        :type resource_group_name: str
        :param if_match: ETag of the certificate.
        :type if_match: str
        :param provisioning_service_name: The name of the provisioning service.
        :type provisioning_service_name: str
        :param certificate_name: This is a mandatory field, and is the logical name of the certificate
         that the provisioning service will access by.
        :type certificate_name: str
        :param certificate_name1: This is optional, and it is the Common Name of the certificate.
        :type certificate_name1: str
        :param certificate_raw_bytes: Raw data within the certificate.
        :type certificate_raw_bytes: bytearray
        :param certificate_is_verified: Indicates if certificate has been verified by owner of the
         private key.
        :type certificate_is_verified: bool
        :param certificate_purpose: A description that mentions the purpose of the certificate.
        :type certificate_purpose: str or ~azure.mgmt.iothubprovisioningservices.models.CertificatePurpose
        :param certificate_created: Time the certificate is created.
        :type certificate_created: ~datetime.datetime
        :param certificate_last_updated: Time the certificate is last updated.
        :type certificate_last_updated: ~datetime.datetime
        :param certificate_has_private_key: Indicates if the certificate contains a private key.
        :type certificate_has_private_key: bool
        :param certificate_nonce: Random number generated to indicate Proof of Possession.
        :type certificate_nonce: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if certificate_name1 is not None:
            query_parameters['certificate.name'] = self._serialize.query("certificate_name1", certificate_name1, 'str')
        if certificate_raw_bytes is not None:
            query_parameters['certificate.rawBytes'] = self._serialize.query("certificate_raw_bytes", certificate_raw_bytes, 'bytearray')
        if certificate_is_verified is not None:
            query_parameters['certificate.isVerified'] = self._serialize.query("certificate_is_verified", certificate_is_verified, 'bool')
        if certificate_purpose is not None:
            query_parameters['certificate.purpose'] = self._serialize.query("certificate_purpose", certificate_purpose, 'str')
        if certificate_created is not None:
            query_parameters['certificate.created'] = self._serialize.query("certificate_created", certificate_created, 'iso-8601')
        if certificate_last_updated is not None:
            query_parameters['certificate.lastUpdated'] = self._serialize.query("certificate_last_updated", certificate_last_updated, 'iso-8601')
        if certificate_has_private_key is not None:
            query_parameters['certificate.hasPrivateKey'] = self._serialize.query("certificate_has_private_key", certificate_has_private_key, 'bool')
        if certificate_nonce is not None:
            query_parameters['certificate.nonce'] = self._serialize.query("certificate_nonce", certificate_nonce, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates/{certificateName}'}  # type: ignore

    async def list(
        self,
        resource_group_name: str,
        provisioning_service_name: str,
        **kwargs: Any
    ) -> "_models.CertificateListDescription":
        """Get all the certificates tied to the provisioning service.

        :param resource_group_name: Name of resource group.
        :type resource_group_name: str
        :param provisioning_service_name: Name of provisioning service to retrieve certificates for.
        :type provisioning_service_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateListDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothubprovisioningservices.models.CertificateListDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateListDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        accept = "application/json"

        # Construct URL
        url = self.list.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateListDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates'}  # type: ignore

    async def generate_verification_code(
        self,
        certificate_name: str,
        if_match: str,
        resource_group_name: str,
        provisioning_service_name: str,
        certificate_name1: Optional[str] = None,
        certificate_raw_bytes: Optional[bytearray] = None,
        certificate_is_verified: Optional[bool] = None,
        certificate_purpose: Optional[Union[str, "_models.CertificatePurpose"]] = None,
        certificate_created: Optional[datetime.datetime] = None,
        certificate_last_updated: Optional[datetime.datetime] = None,
        certificate_has_private_key: Optional[bool] = None,
        certificate_nonce: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.VerificationCodeResponse":
        """Generate verification code for Proof of Possession.

        :param certificate_name: The mandatory logical name of the certificate, that the provisioning
         service uses to access.
        :type certificate_name: str
        :param if_match: ETag of the certificate. This is required to update an existing certificate,
         and ignored while creating a brand new certificate.
        :type if_match: str
        :param resource_group_name: name of resource group.
        :type resource_group_name: str
        :param provisioning_service_name: Name of provisioning service.
        :type provisioning_service_name: str
        :param certificate_name1: Common Name for the certificate.
        :type certificate_name1: str
        :param certificate_raw_bytes: Raw data of certificate.
        :type certificate_raw_bytes: bytearray
        :param certificate_is_verified: Indicates if the certificate has been verified by owner of the
         private key.
        :type certificate_is_verified: bool
        :param certificate_purpose: Description mentioning the purpose of the certificate.
        :type certificate_purpose: str or ~azure.mgmt.iothubprovisioningservices.models.CertificatePurpose
        :param certificate_created: Certificate creation time.
        :type certificate_created: ~datetime.datetime
        :param certificate_last_updated: Certificate last updated time.
        :type certificate_last_updated: ~datetime.datetime
        :param certificate_has_private_key: Indicates if the certificate contains private key.
        :type certificate_has_private_key: bool
        :param certificate_nonce: Random number generated to indicate Proof of Possession.
        :type certificate_nonce: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: VerificationCodeResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.iothubprovisioningservices.models.VerificationCodeResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.VerificationCodeResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        accept = "application/json"

        # Construct URL
        url = self.generate_verification_code.metadata['url']  # type: ignore
        path_format_arguments = {
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if certificate_name1 is not None:
            query_parameters['certificate.name'] = self._serialize.query("certificate_name1", certificate_name1, 'str')
        if certificate_raw_bytes is not None:
            query_parameters['certificate.rawBytes'] = self._serialize.query("certificate_raw_bytes", certificate_raw_bytes, 'bytearray')
        if certificate_is_verified is not None:
            query_parameters['certificate.isVerified'] = self._serialize.query("certificate_is_verified", certificate_is_verified, 'bool')
        if certificate_purpose is not None:
            query_parameters['certificate.purpose'] = self._serialize.query("certificate_purpose", certificate_purpose, 'str')
        if certificate_created is not None:
            query_parameters['certificate.created'] = self._serialize.query("certificate_created", certificate_created, 'iso-8601')
        if certificate_last_updated is not None:
            query_parameters['certificate.lastUpdated'] = self._serialize.query("certificate_last_updated", certificate_last_updated, 'iso-8601')
        if certificate_has_private_key is not None:
            query_parameters['certificate.hasPrivateKey'] = self._serialize.query("certificate_has_private_key", certificate_has_private_key, 'bool')
        if certificate_nonce is not None:
            query_parameters['certificate.nonce'] = self._serialize.query("certificate_nonce", certificate_nonce, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('VerificationCodeResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    generate_verification_code.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates/{certificateName}/generateVerificationCode'}  # type: ignore

    async def verify_certificate(
        self,
        certificate_name: str,
        if_match: str,
        resource_group_name: str,
        provisioning_service_name: str,
        request: "_models.VerificationCodeRequest",
        certificate_name1: Optional[str] = None,
        certificate_raw_bytes: Optional[bytearray] = None,
        certificate_is_verified: Optional[bool] = None,
        certificate_purpose: Optional[Union[str, "_models.CertificatePurpose"]] = None,
        certificate_created: Optional[datetime.datetime] = None,
        certificate_last_updated: Optional[datetime.datetime] = None,
        certificate_has_private_key: Optional[bool] = None,
        certificate_nonce: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.CertificateResponse":
        """Verify certificate's private key possession.

        Verifies the certificate's private key possession by providing the leaf cert issued by the
        verifying pre uploaded certificate.

        :param certificate_name: The mandatory logical name of the certificate, that the provisioning
         service uses to access.
        :type certificate_name: str
        :param if_match: ETag of the certificate.
        :type if_match: str
        :param resource_group_name: Resource group name.
        :type resource_group_name: str
        :param provisioning_service_name: Provisioning service name.
        :type provisioning_service_name: str
        :param request: The name of the certificate.
        :type request: ~azure.mgmt.iothubprovisioningservices.models.VerificationCodeRequest
        :param certificate_name1: Common Name for the certificate.
        :type certificate_name1: str
        :param certificate_raw_bytes: Raw data of certificate.
        :type certificate_raw_bytes: bytearray
        :param certificate_is_verified: Indicates if the certificate has been verified by owner of the
         private key.
        :type certificate_is_verified: bool
        :param certificate_purpose: Describe the purpose of the certificate.
        :type certificate_purpose: str or ~azure.mgmt.iothubprovisioningservices.models.CertificatePurpose
        :param certificate_created: Certificate creation time.
        :type certificate_created: ~datetime.datetime
        :param certificate_last_updated: Certificate last updated time.
        :type certificate_last_updated: ~datetime.datetime
        :param certificate_has_private_key: Indicates if the certificate contains private key.
        :type certificate_has_private_key: bool
        :param certificate_nonce: Random number generated to indicate Proof of Possession.
        :type certificate_nonce: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateResponse, or the result of cls(response)
        :rtype: ~azure.mgmt.iothubprovisioningservices.models.CertificateResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-03-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.verify_certificate.metadata['url']  # type: ignore
        path_format_arguments = {
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'provisioningServiceName': self._serialize.url("provisioning_service_name", provisioning_service_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if certificate_name1 is not None:
            query_parameters['certificate.name'] = self._serialize.query("certificate_name1", certificate_name1, 'str')
        if certificate_raw_bytes is not None:
            query_parameters['certificate.rawBytes'] = self._serialize.query("certificate_raw_bytes", certificate_raw_bytes, 'bytearray')
        if certificate_is_verified is not None:
            query_parameters['certificate.isVerified'] = self._serialize.query("certificate_is_verified", certificate_is_verified, 'bool')
        if certificate_purpose is not None:
            query_parameters['certificate.purpose'] = self._serialize.query("certificate_purpose", certificate_purpose, 'str')
        if certificate_created is not None:
            query_parameters['certificate.created'] = self._serialize.query("certificate_created", certificate_created, 'iso-8601')
        if certificate_last_updated is not None:
            query_parameters['certificate.lastUpdated'] = self._serialize.query("certificate_last_updated", certificate_last_updated, 'iso-8601')
        if certificate_has_private_key is not None:
            query_parameters['certificate.hasPrivateKey'] = self._serialize.query("certificate_has_private_key", certificate_has_private_key, 'bool')
        if certificate_nonce is not None:
            query_parameters['certificate.nonce'] = self._serialize.query("certificate_nonce", certificate_nonce, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(request, 'VerificationCodeRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    verify_certificate.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/provisioningServices/{provisioningServiceName}/certificates/{certificateName}/verify'}  # type: ignore
