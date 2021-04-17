# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._generated import AzureAttestationRestClient
from ._generated.models import AttestationResult, RuntimeData, InitTimeData, DataType, AttestSgxEnclaveRequest, AttestOpenEnclaveRequest
from ._configuration import AttestationClientConfiguration
from ._models import AttestationSigner, AttestationToken, AttestationResponse
import base64
import cryptography
import cryptography.x509
from typing import List, Any
from azure.core.tracing.decorator import distributed_trace
from threading import Lock


class AttestationClient(object):
    """Describes the interface for the per-tenant enclave service.
    :param str base_url: base url of the service
    :param credential: An object which can provide secrets for the attestation service
    :type credential: azure.TokenCredentials or azure.AsyncTokenCredentials
    :keyword Pipeline pipeline: If omitted, the standard pipeline is used.
    :keyword HttpTransport transport: If omitted, the standard pipeline is used.
    :keyword list[HTTPPolicy] policies: If omitted, the standard pipeline is used.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        instance_url,  # type: str
        **kwargs  # type: Any
    ):
        # type: (str, Any, dict) -> None
        base_url = '{instanceUrl}'
        if not credential:
            raise ValueError("Missing credential.")
        self._config = AttestationClientConfiguration(credential, instance_url, **kwargs)
        self._client = AzureAttestationRestClient(credential, instance_url, **kwargs)
        self._statelock = Lock()
        self._signing_certificates = None

    @distributed_trace
    def get_openidmetadata(self):
        """ Retrieves the OpenID metadata configuration document for this attestation instance.
        """
        return self._client.metadata_configuration.get()

    @distributed_trace
    def get_signing_certificates(self): # type: () ->List[AttestationSigner]
        """ Returns the set of signing certificates used to sign attestation tokens.
        """
        signing_certificates = self._client.signing_certificates.get()
        assert signing_certificates.keys is not None
        signers = []
        for key in signing_certificates.keys:
            assert key.x5_c is not None

            # Convert the returned certificate chain into an array of X.509 Certificates.
            certificates = []
            for x5c in key.x5_c:
                der_cert = base64.b64decode(x5c)
                cert = cryptography.x509.load_der_x509_certificate(der_cert)
                certificates.append(cert)
            signers.append(AttestationSigner(certificates, key.kid))
        return signers

    @distributed_trace
    def attest_sgx_enclave(self, quote, init_time_data, init_time_data_is_object, runtime_data, runtime_data_is_object, **kwargs):
        # type(bytes, Any, bool, Any, bool) -> AttestationResponse[AttestationResult]
        runtime = RuntimeData(
            data=runtime_data, 
            data_type=DataType.JSON if runtime_data_is_object else DataType.BINARY) if runtime_data is not None else None
        inittime = InitTimeData(
            data=init_time_data, 
            data_type=DataType.JSON if init_time_data_is_object else DataType.BINARY) if init_time_data is not None else None
        request = AttestSgxEnclaveRequest(quote=quote, init_time_data = inittime, runtime_data = runtime)
        result = self._client.attestation.attest_sgx_enclave(request, **kwargs)
        token = AttestationToken[AttestationResult](token=result.token,
            body_type=AttestationResult)
        return AttestationResponse[AttestationResult](token, token.get_body())

    @distributed_trace
    def attest_open_enclave(self, report, init_time_data, init_time_data_is_object, runtime_data, runtime_data_is_object, **kwargs):
        # type(bytes, Any, bool, Any, bool) -> AttestationResponse[AttestationResult]
        runtime = RuntimeData(
            data=runtime_data, 
            data_type=DataType.JSON if runtime_data_is_object else DataType.BINARY) if runtime_data is not None else None
        inittime = InitTimeData(
            data=init_time_data, 
            data_type=DataType.JSON if init_time_data_is_object else DataType.BINARY) if init_time_data is not None else None
        request = AttestOpenEnclaveRequest(report=report, init_time_data = inittime, runtime_data = runtime)
        result = self._client.attestation.attest_open_enclave(request, **kwargs)
        token = AttestationToken[AttestationResult](token=result.token,
            body_type=AttestationResult)
        token.validate_token(self._config.token_validation_options, self._get_signers())
        return AttestationResponse[AttestationResult](token, token.get_body())

    def _get_signers(self):
        #type() -> List[AttestationSigner]
        """ Returns the set of signing certificates used to sign attestation tokens.
        """

        with self._statelock:
            if (self._signing_certificates == None):
                signing_certificates = self._client.signing_certificates.get()
                self._signing_certificates = []
                for key in signing_certificates.keys:
                    # Convert the returned certificate chain into an array of X.509 Certificates.
                    certificates = []
                    for x5c in key.x5_c:
                        der_cert = base64.b64decode(x5c)
                        cert = cryptography.x509.load_der_x509_certificate(der_cert)
                        certificates.append(cert)
                    self._signing_certificates.append(AttestationSigner(certificates, key.kid))
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
