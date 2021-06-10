# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

from typing import Dict, List, Any, Optional, TYPE_CHECKING

from azure.core import PipelineClient

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials_async import AsyncTokenCredential
    from azure.core._pipeline_client_async import AsyncPipelineClient

from .._generated.aio import AzureAttestationRestClient
from .._generated.models import (
    AttestationResult as GeneratedAttestationResult,
    RuntimeData,
    InitTimeData,
    DataType,
    AttestSgxEnclaveRequest,
    AttestOpenEnclaveRequest)
from .._configuration import AttestationClientConfiguration
from .._models import (
    AttestationSigner,
    AttestationToken,
    AttestationResult,
    AttestationData,
    AttestationTokenValidationException)
import base64
from threading import Lock

from azure.core.tracing.decorator_async import distributed_trace_async


class AttestationClient(object):
    """An AttestationClient object enables access to the Attestation family of APIs provided
      by the attestation service.

    :param credential: Credentials for the caller used to interact with the service.
    :type credential: :class:`~azure.core.credentials_async.AsyncTokenCredential`
    :param str endpoint: The attestation instance base URI, for example https://mytenant.attest.azure.net.
    :keyword ~azure.core.pipeline.AsyncPipelineClient pipeline: If omitted, the standard pipeline is used.
    :keyword ~azure.core.pipeline.transport.AsyncHttpTransport transport: If omitted, the standard pipeline is used.
    :keyword list[~azure.core.pipeline.policies.AsyncHTTPPolicy] policies: If omitted, the standard pipeline is used.

    For additional client creation configuration options, please see https://aka.ms/azsdk/python/options.

    """
    def __init__(
        self,
        credential,  # type: 'AsyncTokenCredential'
        endpoint, #type: str
        **kwargs #type: Any
    ): #type: (...) -> None
        if not credential:
            raise ValueError("Missing credential.")
        self._config = AttestationClientConfiguration(**kwargs)
        self._client = AzureAttestationRestClient(credential, endpoint, **kwargs)
        self._statelock = Lock()
        self._signing_certificates = None

    @distributed_trace_async
    async def get_openidmetadata(
        self, 
        **kwargs #type: Any
        ): #type: (...) -> Any
        """ Retrieves the OpenID metadata configuration document for this attestation instance.

        :return: OpenId Metadata document for the attestation service instance.
        :rtype: Any
        """
        return await self._client.metadata_configuration.get(**kwargs)

    @distributed_trace_async
    async def get_signing_certificates(
        self, 
        **kwargs #type: Any
        ): #type: (...) -> List[AttestationSigner]
        """ Returns the set of signing certificates used to sign attestation tokens.

        :return: A list of :class:`azure.security.attestation.AttestationSigner` objects.
        :rtype: list[azure.security.attestation.AttestationSigner]

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """
        signing_certificates = await self._client.signing_certificates.get(**kwargs)
        signers = []
        for key in signing_certificates.keys:
            signers.append(AttestationSigner._from_generated(key))
        return signers

    @distributed_trace_async
    async def attest_sgx_enclave(
        self,
        quote : bytes,
        inittime_data=None, #type: AttestationData
        runtime_data=None, #type: AttestationData
        **kwargs #type:Any
        ): #type: (...) -> AttestationResult
        """ Attests the validity of an SGX quote.

        :param bytes quote: An SGX quote generated from an Intel(tm) SGX enclave
        :param inittime_data: Data presented at the time that the SGX enclave was initialized.
        :type inittime_data: azure.security.attestation.AttestationData
        :param runtime_data: Data presented at the time that the SGX quote was created.
        :type runtime_data: azure.security.attestation.AttestationData
        :keyword draft_policy: "draft" or "experimental" policy to be used with
            this attestation request. If this parameter is provided, then this 
            policy document will be used for the attestation request.
            This allows a caller to test various policy documents against actual data
            before applying the policy document via the set_policy API
        :paramtype draft_policy: str
        :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
        :keyword validation_callback: Callback to allow clients to perform custom validation of the token.
        :paramtype validation_callback: Callable[[AttestationToken, AttestationSigner], bool]
        :keyword bool validate_signature: if True, validate the signature of the token being validated.
        :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
        :keyword str issuer: Expected issuer, used if validate_issuer is true.
        :keyword float validation_slack: Slack time for validation - tolerance applied 
            to help account for clock drift between the issuer and the current machine.
        :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
        :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.

        :return: Attestation service response encapsulating an :class:`AttestationResult`.
        :rtype: azure.security.attestation.AttestationResult

        .. note::
            Note that if the `draft_policy` parameter is provided, the resulting attestation token will be an unsecured attestation token.

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """
        runtime = None
        if runtime_data:
            runtime = RuntimeData(data=runtime_data._data, data_type=DataType.JSON if runtime_data._is_json else DataType.BINARY)

        inittime = None
        if inittime_data:
            inittime = InitTimeData(data=inittime_data._data, data_type=DataType.JSON if inittime_data._is_json else DataType.BINARY)

        request = AttestSgxEnclaveRequest(
            quote=quote,
            init_time_data = inittime,
            runtime_data = runtime,
            draft_policy_for_attestation=kwargs.pop('draft_policy', None))

        result = await self._client.attestation.attest_sgx_enclave(request, **kwargs)
        token = AttestationToken[GeneratedAttestationResult](token=result.token,
            body_type=GeneratedAttestationResult)
        # Merge our existing config options with the options for this API call. 
        options = self._config._args.copy()
        options.update(**kwargs)

        if options.get("validate_token", True):
            if not token.validate_token(await self._get_signers(**kwargs), **options):
                raise AttestationTokenValidationException("Could not validate token returned for the attest_sgx_enclave API")
        return AttestationResult._from_generated(token.get_body(), token)

    @distributed_trace_async
    async def attest_open_enclave(
        self,
        report : bytes,
        inittime_data=None, #type: AttestationData
        runtime_data=None, #type: AttestationData
        **kwargs #type: Any
        ): #type: (...) -> AttestationResult
        """ Attests the validity of an Open Enclave report.

        :param bytes report: An open_enclave report generated from an Intel(tm) SGX enclave
        :param inittime_data: Data presented at the time that the SGX enclave was initialized.
        :type inittime_data: azure.security.attestation.AttestationData
        :param runtime_data: Data presented at the time that the open_enclave report was created.
        :type runtime_data: azure.security.attestation.AttestationData
        :keyword draft_policy: "draft" or "experimental" policy to be used with
            this attestation request. If this parameter is provided, then this 
            policy document will be used for the attestation request.
            This allows a caller to test various policy documents against actual data
            before applying the policy document via the set_policy API.

        :paramtype draft_policy: str
        :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
        :keyword validation_callback: Callback to allow clients to perform custom validation of the token.
        :paramtype validation_callback: Callable[[AttestationToken, AttestationSigner], bool]
        :keyword bool validate_signature: if True, validate the signature of the token being validated.
        :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
        :keyword str issuer: Expected issuer, used if validate_issuer is true.
        :keyword float validation_slack: Slack time for validation - tolerance applied 
            to help account for clock drift between the issuer and the current machine.
        :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
        :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.
        :return: Attestation service response encapsulating an :class:`AttestationResult`.
        :rtype: azure.security.attestation.AttestationResult

        .. note::
            Note that if the `draft_policy` parameter is provided, the resulting attestation token will be an unsecured attestation token.

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """

        runtime = None
        if runtime_data:
            runtime = RuntimeData(data=runtime_data._data, data_type=DataType.JSON if runtime_data._is_json else DataType.BINARY)

        inittime = None
        if inittime_data:
            inittime = InitTimeData(data=inittime_data._data, data_type=DataType.JSON if inittime_data._is_json else DataType.BINARY)
        request = AttestOpenEnclaveRequest(
            report=report,
            init_time_data = inittime,
            runtime_data = runtime,
            draft_policy_for_attestation = kwargs.pop('draft_policy', None))
        result = await self._client.attestation.attest_open_enclave(request, **kwargs)
        token = AttestationToken[GeneratedAttestationResult](token=result.token,
            body_type=GeneratedAttestationResult)
        # Merge our existing config options with the options for this API call. 
        options = self._config._args.copy()
        options.update(**kwargs)

        if options.get("validate_token", True):
            if not token.validate_token(await self._get_signers(**kwargs), **options):
                raise AttestationTokenValidationException("Could not validate token returned for the attest_open_enclave API")
        return AttestationResult._from_generated(token.get_body(), token)

    @distributed_trace_async
    async def attest_tpm(
        self, 
        request, #type: str
        **kwargs #type: Any
        ): #type: (...) -> str
        """ Attest a TPM based enclave.

        See the `TPM Attestation Protocol Reference <https://docs.microsoft.com/en-us/azure/attestation/virtualization-based-security-protocol>`_ for more information.

        :param request: Incoming request to send to the TPM attestation service.
        :type request: str
        :returns: A structure containing the response from the TPM attestation.
        :rtype: str
        """
        response = await self._client.attestation.attest_tpm(request.encode('ascii'), **kwargs)
        return response.data.decode('ascii')

    async def _get_signers(self, **kwargs: Any): #type: (Any) -> list[AttestationSigner]
        """ Returns the set of signing certificates used to sign attestation tokens.
        """

        with self._statelock:
            if self._signing_certificates is None:
                signing_certificates = await self._client.signing_certificates.get(**kwargs)
                self._signing_certificates = []
                for key in signing_certificates.keys:
                    self._signing_certificates.append(AttestationSigner._from_generated(key))
            signers = self._signing_certificates
        return signers

    async def close(self):
        # type: () -> None
        await self._client.close()

    async def __aenter__(self):
        # type: () -> AttestationClient
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details):
        # type: (Any) -> None
        await self._client.__aexit__(*exc_details)
