# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class CertificatesOperations(object):
    """CertificatesOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.iothub.v2019_07_01_preview.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list_by_iot_hub(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CertificateListDescription"
        """Get the certificate list.

        Returns the list of certificates.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateListDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateListDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateListDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.list_by_iot_hub.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateListDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    list_by_iot_hub.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates'}  # type: ignore

    def get(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        certificate_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CertificateDescription"
        """Get the certificate.

        Returns the certificate.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :param certificate_name: The name of the certificate.
        :type certificate_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', pattern=r'^[A-Za-z0-9-._]{1,64}$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates/{certificateName}'}  # type: ignore

    def create_or_update(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        certificate_name,  # type: str
        certificate_description,  # type: "_models.CertificateBodyDescription"
        if_match=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CertificateDescription"
        """Upload the certificate to the IoT hub.

        Adds new or replaces existing certificate.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :param certificate_name: The name of the certificate.
        :type certificate_name: str
        :param certificate_description: The certificate body.
        :type certificate_description: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateBodyDescription
        :param if_match: ETag of the Certificate. Do not specify for creating a brand new certificate.
         Required to update an existing certificate.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', pattern=r'^[A-Za-z0-9-._]{1,64}$'),
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
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('CertificateDescription', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('CertificateDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates/{certificateName}'}  # type: ignore

    def delete(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        certificate_name,  # type: str
        if_match,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Delete an X509 certificate.

        Deletes an existing X509 certificate or does nothing if it does not exist.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :param certificate_name: The name of the certificate.
        :type certificate_name: str
        :param if_match: ETag of the Certificate.
        :type if_match: str
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
        api_version = "2019-07-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', pattern=r'^[A-Za-z0-9-._]{1,64}$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates/{certificateName}'}  # type: ignore

    def generate_verification_code(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        certificate_name,  # type: str
        if_match,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CertificateWithNonceDescription"
        """Generate verification code for proof of possession flow.

        Generates verification code for proof of possession flow. The verification code will be used to
        generate a leaf certificate.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :param certificate_name: The name of the certificate.
        :type certificate_name: str
        :param if_match: ETag of the Certificate.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateWithNonceDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateWithNonceDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateWithNonceDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.generate_verification_code.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', pattern=r'^[A-Za-z0-9-._]{1,64}$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateWithNonceDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    generate_verification_code.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates/{certificateName}/generateVerificationCode'}  # type: ignore

    def verify(
        self,
        resource_group_name,  # type: str
        resource_name,  # type: str
        certificate_name,  # type: str
        if_match,  # type: str
        certificate_verification_body,  # type: "_models.CertificateVerificationDescription"
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CertificateDescription"
        """Verify certificate's private key possession.

        Verifies the certificate's private key possession by providing the leaf cert issued by the
        verifying pre uploaded certificate.

        :param resource_group_name: The name of the resource group that contains the IoT hub.
        :type resource_group_name: str
        :param resource_name: The name of the IoT hub.
        :type resource_name: str
        :param certificate_name: The name of the certificate.
        :type certificate_name: str
        :param if_match: ETag of the Certificate.
        :type if_match: str
        :param certificate_verification_body: The name of the certificate.
        :type certificate_verification_body: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateVerificationDescription
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CertificateDescription, or the result of cls(response)
        :rtype: ~azure.mgmt.iothub.v2019_07_01_preview.models.CertificateDescription
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CertificateDescription"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.verify.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', pattern=r'^[A-Za-z0-9-._]{1,64}$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(certificate_verification_body, 'CertificateVerificationDescription')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorDetails, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('CertificateDescription', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    verify.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}/certificates/{certificateName}/verify'}  # type: ignore
