# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------

from typing import NoReturn, TYPE_CHECKING

from azure.core.configuration import Configuration
from azure.core.pipeline import policies

from ._version import VERSION

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any
    from azure.core.credentials import TokenCredential


class AttestationClientConfiguration(Configuration):
    """Configuration for AttestationClient.

    Note that all parameters used to create this instance are saved as instance
    attributes.

    :keyword bool validate_token: if True, validate the token, otherwise return the token unvalidated.
    :keyword validation_callback: Function callback to allow clients to perform custom validation of the token.
        if the token is invalid, the `validation_callback` function should throw 
        an exception.
    :paramtype validation_callback: Callable[[AttestationToken, AttestationSigner], None]
    :keyword bool validate_signature: if True, validate the signature of the token being validated.
    :keyword bool validate_expiration: If True, validate the expiration time of the token being validated.
    :keyword str issuer: Expected issuer, used if validate_issuer is true.
    :keyword float validation_slack: Slack time for validation - tolerance applied 
        to help account for clock drift between the issuer and the current machine.
    :keyword bool validate_issuer: If True, validate that the issuer of the token matches the expected issuer.
    :keyword bool validate_not_before_time: If true, validate the "Not Before" time in the token.
    """

    def __init__(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        super(AttestationClientConfiguration, self).__init__(**kwargs)

        self._args = kwargs.copy()
