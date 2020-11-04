# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
import os
import re
import tempfile
import typing

INGESTION_ENDPOINT = "ingestionendpoint"
INSTRUMENTATION_KEY = "instrumentationkey"
TEMPDIR_PREFIX = "opentelemetry-python-"

# Validate UUID format
# Specs taken from https://tools.ietf.org/html/rfc4122
uuid_regex_pattern = re.compile(
    "^[0-9a-f]{8}-"
    "[0-9a-f]{4}-"
    "[1-5][0-9a-f]{3}-"
    "[89ab][0-9a-f]{3}-"
    "[0-9a-f]{12}$"
)


class BaseObject:
    __slots__ = ()

    def __repr__(self):
        tmp = {}

        for key in self.__slots__:
            data = getattr(self, key, None)
            if isinstance(data, BaseObject):
                tmp[key] = repr(data)
            else:
                tmp[key] = data

        return repr(tmp)


class ExporterOptions(BaseObject):
    """Options to configure Azure exporters.

    Args:
        connection_string: Azure Connection String.
        instrumentation_key: Azure Instrumentation Key.
        proxies: Proxies to pass Azure Monitor request through.
        storage_maintenance_period: Local storage maintenance interval in seconds.
        storage_max_size: Local storage maximum size in bytes.
        storage_path: Local storage file path.
        storage_retention_period: Local storage retention period in seconds
        timeout: Request timeout in seconds
    """

    __slots__ = (
        "connection_string",
        "endpoint",
        "instrumentation_key",
        "proxies",
        "storage_maintenance_period",
        "storage_max_size",
        "storage_path",
        "storage_retention_period",
        "timeout",
    )

    def __init__(
        self,
        connection_string: str = None,
        instrumentation_key: str = None,
        proxies: typing.Dict[str, str] = None,
        storage_maintenance_period: int = 60,
        storage_max_size: int = 50 * 1024 * 1024,
        storage_path: str = None,
        storage_retention_period: int = 7 * 24 * 60 * 60,
        timeout: int = 10.0,  # networking timeout in seconds
    ) -> None:
        self.connection_string = connection_string
        self.instrumentation_key = instrumentation_key
        self.proxies = proxies
        self.storage_maintenance_period = storage_maintenance_period
        self.storage_max_size = storage_max_size
        self.storage_path = storage_path
        self.storage_retention_period = storage_retention_period
        self.timeout = timeout
        self.endpoint = ""
        self._initialize()
        self._validate_instrumentation_key()

    def _initialize(self) -> None:
        # connection string and ikey
        code_cs = parse_connection_string(self.connection_string)
        code_ikey = self.instrumentation_key
        env_cs = parse_connection_string(
            os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
        )
        env_ikey = os.getenv("APPINSIGHTS_INSTRUMENTATIONKEY")

        # The priority of which value takes on the instrumentation key is:
        # 1. Key from explicitly passed in connection string
        # 2. Key from explicitly passed in instrumentation key
        # 3. Key from connection string in environment variable
        # 4. Key from instrumentation key in environment variable
        self.instrumentation_key = (
            code_cs.get(INSTRUMENTATION_KEY)
            or code_ikey
            or env_cs.get(INSTRUMENTATION_KEY)
            or env_ikey
        )
        # The priority of the ingestion endpoint is as follows:
        # 1. The endpoint explicitly passed in connection string
        # 2. The endpoint from the connection string in environment variable
        # 3. The default breeze endpoint
        self.endpoint = (
            code_cs.get(INGESTION_ENDPOINT)
            or env_cs.get(INGESTION_ENDPOINT)
            or "https://dc.services.visualstudio.com"
        )

        # proxies
        if self.proxies is None:
            self.proxies = {}

        # storage path
        if self.storage_path is None:
            temp_suffix = self.instrumentation_key or ""
            self.storage_path = os.path.join(
                tempfile.gettempdir(), TEMPDIR_PREFIX + temp_suffix
            )

    def _validate_instrumentation_key(self) -> None:
        """Validates the instrumentation key used for Azure Monitor.
        An instrumentation key cannot be null or empty. An instrumentation key
        is valid for Azure Monitor only if it is a valid UUID.
        :param instrumentation_key: The instrumentation key to validate
        """
        if not self.instrumentation_key:
            raise ValueError("Instrumentation key cannot be none or empty.")
        match = uuid_regex_pattern.match(self.instrumentation_key)
        if not match:
            raise ValueError("Invalid instrumentation key. It should be a valid UUID.")


def parse_connection_string(connection_string) -> typing.Dict:
    if connection_string is None:
        return {}
    try:
        pairs = connection_string.split(";")
        result = dict(s.split("=") for s in pairs)
        # Convert keys to lower-case due to case type-insensitive checking
        result = {key.lower(): value for key, value in result.items()}
    except Exception:
        # pylint: disable=raise-missing-from
        raise ValueError("Invalid connection string")
    # Validate authorization
    auth = result.get("authorization")
    if auth is not None and auth.lower() != "ikey":
        raise ValueError("Invalid authorization mechanism")
    # Construct the ingestion endpoint if not passed in explicitly
    if result.get(INGESTION_ENDPOINT) is None:
        endpoint_suffix = ""
        location_prefix = ""
        suffix = result.get("endpointsuffix")
        if suffix is not None:
            endpoint_suffix = suffix
            # Get regional information if provided
            prefix = result.get("location")
            if prefix is not None:
                location_prefix = prefix + "."
            endpoint = "https://{0}dc.{1}".format(
                location_prefix, endpoint_suffix
            )
            result[INGESTION_ENDPOINT] = endpoint
        else:
            # Default to None if cannot construct
            result[INGESTION_ENDPOINT] = None
    return result
