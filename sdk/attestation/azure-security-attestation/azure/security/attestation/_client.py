# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

import json
from typing import Dict, List, Any, Optional, TYPE_CHECKING, Tuple, Union

from azure.core import PipelineClient

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._generated import AzureAttestationRestClient
from ._generated.models import (
    AttestationResult as GeneratedAttestationResult,
    RuntimeData,
    InitTimeData,
    DataType,
    AttestSgxEnclaveRequest,
    AttestOpenEnclaveRequest,
)
from ._configuration import AttestationClientConfiguration
from ._models import AttestationSigner, AttestationToken, AttestationResult
from ._common import pem_from_base64, validate_signing_keys, merge_validation_args
from json import JSONDecoder

from azure.core.tracing.decorator import distributed_trace
from threading import Lock


class AttestationClient(object):
    """An AttestationClient object enables access to the Attestation family of APIs provided
      by the attestation service.

    :param credential: Credentials for the caller used to interact with the service.
    :type credential: :class:`~azure.core.credentials.TokenCredential`
    :param str endpoint: The attestation instance base URI, for example https://mytenant.attest.azure.net.
    :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
    :keyword validation_callback: Function callback to allow clients to perform custom validation of the token.
        if the token is invalid, the `validation_callback` function should throw
        an exception.
    :paramtype validation_callback: ~typing.Callable[[AttestationToken, AttestationSigner], None]
    :keyword bool validate_signature: if True, validate the signature of the token being validated.
    :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
    :keyword str issuer: Expected issuer, used if validate_issuer is true.
    :keyword float validation_slack: Slack time for validation - tolerance applied
        to help account for clock drift between the issuer and the current machine.
    :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
    :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.

    .. tip::
        The `validate_token`, `validation_callback`, `validate_signature`,
        `validate_expiration`, `validate_not_before_time`, `validate_issuer`, and
        `issuer` keyword arguments are default values applied to each API call within
        the :py:class:`AttestationClient` class. These values can be
        overridden on individual API calls as needed.


    For additional client creation configuration options, please see https://aka.ms/azsdk/python/options.

    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        endpoint,  # type: str
        **kwargs  # type: Any
    ):
        # type: (TokenCredential, str, Any) -> None

        if not credential:
            raise ValueError("Missing credential.")
        self._config = AttestationClientConfiguration(**kwargs)
        self._client = AzureAttestationRestClient(credential, endpoint, **kwargs)
        self._statelock = Lock()
        self._signing_certificates = None

    @distributed_trace
    def get_openidmetadata(self, **kwargs):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        """Retrieves the OpenID metadata configuration document for this attestation instance.

        The metadata configuration document is defined in the `OpenID Connect Discovery <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse>` specification.

        The attestation service currently returns the following fields:
        * issuer
        * jwks_uri
        * claims_supported

        :return: OpenID metadata configuration
        :rtype: Dict[str, Any]
        """
        return self._client.metadata_configuration.get(**kwargs)

    @distributed_trace
    def get_signing_certificates(self, **kwargs):
        # type: (Any) -> List[AttestationSigner]
        """Returns the set of signing certificates used to sign attestation tokens.

        :return: A list of :class:`azure.security.attestation.AttestationSigner` objects.

        :rtype: List[~azure.security.attestation.AttestationSigner]

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """
        signing_certificates = self._client.signing_certificates.get(**kwargs)
        signers = []
        for key in signing_certificates.keys:
            # Convert the returned certificate chain into an array of X.509 Certificates.
            signers.append(AttestationSigner._from_generated(key))
        return signers

    @distributed_trace
    def attest_sgx_enclave(
        self,
        quote,  # type: bytes
        **kwargs  # type: Dict[str, Any]
    ):  # type: (...) -> Tuple[AttestationResult, AttestationToken]
        """Attests the validity of an SGX quote.

        :param bytes quote: An SGX quote generated from an Intel(tm) SGX enclave
        :keyword bytes inittime_data: Data presented at the time that the SGX
            enclave was initialized.
        :keyword bytes inittime_json: Data presented at the time that the SGX
            enclave was initialized, JSON encoded.
        :keyword bytes runtime_data: Data presented at the time that the open_enclave
            report was created.
        :keyword bytes runtime_json: Data presented at the time that the open_enclave
            report was created. JSON Encoded.
        :keyword str draft_policy: "draft" or "experimental" policy to be used with
            this attestation request. If this parameter is provided, then this
            policy document will be used for the attestation request.
            This allows a caller to test various policy documents against actual data
            before applying the policy document via the set_policy API
        :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
        :keyword validation_callback: Function callback to allow clients to perform custom validation of the token.
            if the token is invalid, the `validation_callback` function should throw
            an exception.
        :paramtype validation_callback: ~typing.Callable[[AttestationToken, AttestationSigner], None]
        :keyword bool validate_signature: if True, validate the signature of the token being validated.
        :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
        :keyword str issuer: Expected issuer, used if validate_issuer is true.
        :keyword float validation_slack: Slack time for validation - tolerance applied
            to help account for clock drift between the issuer and the current machine.
        :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
        :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.


        :return: :class:`AttestationResult` containing the claims in the returned attestation token.

        :rtype: Tuple[~azure.security.attestation.AttestationResult, ~azure.security.attestation.AttestationToken]

        .. note::
            Note that if the `draft_policy` parameter is provided, the resulting attestation token will be an unsecured attestation token.

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_attest_enclave.py
                :start-after: [START attest_sgx_enclave_shared]
                :end-before: [END attest_sgx_enclave_shared]
                :language: python
                :dedent: 8
                :caption: Attesting an SGX Enclave

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """

        inittime_json = kwargs.pop("inittime_json", None)  # type: bytes
        inittime_data = kwargs.pop("inittime_data", None)  # type: bytes
        runtime_json = kwargs.pop("runtime_json", None)  # type: bytes
        runtime_data = kwargs.pop("runtime_data", None)  # type: bytes

        if inittime_json and inittime_data:
            raise ValueError("Cannot provide both inittime_json and inittime_data.")
        if runtime_json and runtime_data:
            raise ValueError("Cannot provide both runtime_data and runtime_json.")

        # If the input was JSON, make sure that it's valid JSON before sending it
        # to the service.
        if inittime_json:
            json.loads(inittime_json)

        if runtime_json:
            json.loads(runtime_json)

        runtime = None
        if runtime_data:
            runtime = RuntimeData(data=runtime_data, data_type=DataType.BINARY)

        if runtime_json:
            runtime = RuntimeData(data=runtime_json, data_type=DataType.JSON)

        inittime = None
        if inittime_data:
            inittime = InitTimeData(data=inittime_data, data_type=DataType.BINARY)
        if inittime_json:
            inittime = InitTimeData(data=inittime_data, data_type=DataType.JSON)

        request = AttestSgxEnclaveRequest(
            quote=quote,
            init_time_data=inittime,
            runtime_data=runtime,
            draft_policy_for_attestation=kwargs.pop("draft_policy", None),
        )

        # Merge our existing config options with the options for this API call.
        # Note that this must be done before calling into the implementation
        # layer because the implementation layer doesn't like keyword args that
        # it doesn't expect :(.
        options = merge_validation_args(self._config._kwargs, kwargs)

        result = self._client.attestation.attest_sgx_enclave(request, **kwargs)
        token = AttestationToken(
            token=result.token, body_type=GeneratedAttestationResult
        )

        if options.get("validate_token", True):
            token._validate_token(self._get_signers(**kwargs), **options)

        return AttestationResult._from_generated(token._get_body()), token

    @distributed_trace
    def attest_open_enclave(
        self, report, **kwargs  # type: Dict[str, Any]
    ):  # type: (...) -> Tuple[AttestationResult, AttestationToken]
        """Attests the validity of an Open Enclave report.

        :param bytes report: An open_enclave report generated from an Intel(tm)
            SGX enclave
        :keyword bytes inittime_data: Data presented at the time that the SGX
            enclave was initialized.
        :keyword bytes inittime_json: Data presented at the time that the SGX
            enclave was initialized, JSON encoded.
        :keyword bytes runtime_data: Data presented at the time that the open_enclave
            report was created.
        :keyword bytes runtime_json: Data presented at the time that the open_enclave
            report was created. JSON Encoded.
        :keyword str draft_policy: "draft" or "experimental" policy to be used with
            this attestation request. If this parameter is provided, then this
            policy document will be used for the attestation request.
            This allows a caller to test various policy documents against actual data
            before applying the policy document via the set_policy API.

        :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
        :keyword validation_callback: Function callback to allow clients to perform custom validation of the token.
            if the token is invalid, the `validation_callback` function should throw
            an exception.
        :paramtype validation_callback: ~typing.Callable[[AttestationToken, AttestationSigner], None]
        :keyword bool validate_signature: if True, validate the signature of the token being validated.
        :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
        :keyword str issuer: Expected issuer, used if validate_issuer is true.
        :keyword float validation_slack: Slack time for validation - tolerance applied
            to help account for clock drift between the issuer and the current machine.
        :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
        :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.

        :return: :class:`AttestationResult` containing the claims in the returned attestation token.

        :rtype: Tuple[~azure.security.attestation.AttestationResult, ~azure.security.attestation.AttestationToken]

        .. admonition:: Example: Simple OpenEnclave attestation.

            .. literalinclude:: ../samples/sample_attest_enclave.py
                :start-after: [START attest_open_enclave_shared]
                :end-before: [END attest_open_enclave_shared]
                :language: python
                :dedent: 8
                :caption: Attesting an open_enclave report for an SGX enclave.

        .. admonition:: Example: Simple OpenEnclave attestation with draft attestation policy.


            .. literalinclude:: ../samples/sample_attest_enclave.py
                :start-after: [START attest_open_enclave_shared_draft]
                :end-before: [END attest_open_enclave_shared_draft]
                :language: python
                :dedent: 8
                :caption: Attesting using a draft attestation policy.


        .. note::
            Note that if the `draft_policy` parameter is provided, the resulting attestation token will be an unsecured attestation token.

        For additional request configuration options, please see `Python Request Options <https://aka.ms/azsdk/python/options>`_.

        """

        inittime_json = kwargs.pop("inittime_json", None)  # type: bytes
        inittime_data = kwargs.pop("inittime_data", None)  # type: bytes
        runtime_json = kwargs.pop("runtime_json", None)  # type: bytes
        runtime_data = kwargs.pop("runtime_data", None)  # type: bytes

        if inittime_json and inittime_data:
            raise ValueError("Cannot provide both inittime_json and inittime_data.")
        if runtime_json and runtime_data:
            raise ValueError("Cannot provide both runtime_data and runtime_json.")

        # If the input was JSON, make sure that it's valid JSON before sending it
        # to the service.
        if inittime_json:
            json.loads(inittime_json)

        if runtime_json:
            json.loads(runtime_json)

        # Now create the RuntimeData object to be sent to the service.
        runtime = None
        if runtime_data:
            runtime = RuntimeData(data=runtime_data, data_type=DataType.BINARY)

        if runtime_json:
            runtime = RuntimeData(data=runtime_json, data_type=DataType.JSON)

        # And the InitTimeData object to be sent to the service.
        inittime = None
        if inittime_data:
            inittime = InitTimeData(data=inittime_data, data_type=DataType.BINARY)
        if inittime_json:
            inittime = InitTimeData(data=inittime_data, data_type=DataType.JSON)

        request = AttestOpenEnclaveRequest(
            report=report,
            init_time_data=inittime,
            runtime_data=runtime,
            draft_policy_for_attestation=kwargs.pop("draft_policy", None),
        )

        # Merge our existing config options with the options for this API call.
        # Note that this must be done before calling into the implementation
        # layer because the implementation layer doesn't like keyword args that
        # it doesn't expect :(.
        options = merge_validation_args(self._config._kwargs, kwargs)

        result = self._client.attestation.attest_open_enclave(request, **kwargs)
        token = AttestationToken(
            token=result.token, body_type=GeneratedAttestationResult
        )

        if options.get("validate_token", True):
            token._validate_token(self._get_signers(**kwargs), **options)
        return AttestationResult._from_generated(token._get_body()), token

    @distributed_trace
    def attest_tpm(self, content, **kwargs):
        # type: (str, **Any) -> str
        """Attest a TPM based enclave.

        See the `TPM Attestation Protocol Reference <https://docs.microsoft.com/en-us/azure/attestation/virtualization-based-security-protocol>`_ for more information.

        :param str content: Data to send to the TPM attestation service.
        :returns: A structure containing the response from the TPM attestation.
        :rtype: str
        """

        response = self._client.attestation.attest_tpm(
            content.encode("ascii"), **kwargs
        )
        return response.data.decode("ascii")

    def _get_signers(self, **kwargs):
        # type: (Any) -> list[AttestationSigner]
        """Returns the set of signing certificates used to sign attestation tokens."""

        with self._statelock:
            if self._signing_certificates is None:
                signing_certificates = self._client.signing_certificates.get(**kwargs)
                self._signing_certificates = []
                for key in signing_certificates.keys:
                    # Convert the returned certificate chain into an array of X.509 Certificates.
                    self._signing_certificates.append(
                        AttestationSigner._from_generated(key)
                    )
            signers = self._signing_certificates
        return signers

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> AttestationClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
