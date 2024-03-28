# +------------------------------------+
#
#           SCRAPI Tool Index
#
# +------------------------------------+
#  Thank you users! We ❤️ you! - Krrish & Ishaan
## Use a SCRAPI feed as an index for tools available within 2nd and 3rd party
## catalogs. First party is the client.
import json
import asyncio
import base64
import hashlib
import tempfile
import pathlib
import traceback
from typing import Optional, Literal, List, Any, AsyncIterator

from pydantic import Field, root_validator
from fastapi import HTTPException
import litellm
from litellm.caching import DualCache
from litellm.proxy._types import UserAPIKeyAuth, LiteLLMBase
from litellm.integrations.custom_logger import CustomLogger
from litellm._logging import verbose_proxy_logger
from litellm.utils import get_formatted_prompt
from litellm.main import (
    make_tool_calls_list,
    make_function_call_name_and_combined_arguments,
)

import scitt_emulator.create_statement
import scitt_emulator.client
import scitt_emulator.did_helpers

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

import snoop


@tool
def historical_stock_prices(ticker: str) -> str:
    "Get the historical stock prices for a stock ticker"
    return json.dumps(
        [
            ("2024-03-22", 42.0),
            ("2024-03-23", 52.0),
            ("2024-03-24", 62.0),
        ]
    )


class SCRAPISCRAPIInstance(LiteLLMBase, extra='forbid'):
    url: str
    token: Optional[str] = None
    ca_cert: Optional[Any] = None
    private_key_pem: Optional[str] = None
    issuer: Optional[str] = None
    # TODO subject should be the URN of the transparent statement
    # which is the schema for the manifest. We'll shorthand that to
    # an identifier until we setup that flow and discovery via
    # json-ld and pydantic schema dump.
    subject: Optional[str] = "tool_index.proxy.llm"


class LiteLLMSCRAPIToolIndexParams(LiteLLMBase, extra='forbid'):
    scrapi_instances: list[SCRAPISCRAPIInstance] = Field(
        default_factory=lambda: [],
    )


class LiteLLMSCRAPIToolIndex(CustomLogger):
    def __init__(
        self,
        scrapi_tool_index_params: Optional[LiteLLMSCRAPIToolIndexParams] = None,
    ):
        self.scrapi_tool_index_params = scrapi_tool_index_params

        self.llm_router: Optional[litellm.Router] = None

    def print_verbose(self, print_statement, level: Literal["INFO", "DEBUG"] = "DEBUG"):
        if level == "INFO":
            verbose_proxy_logger.info(print_statement)
        elif level == "DEBUG":
            verbose_proxy_logger.debug(print_statement)

        if litellm.set_verbose is True:
            print(print_statement)  # noqa

    def update_environment(self, router: Optional[litellm.Router] = None):
        self.llm_router = router

        if self.scrapi_tool_index_params is None:
            return

        params = self.scrapi_tool_index_params
        self.print_verbose(f"params: {params}")

    async def aiter_tools(
        self,
        # TODO Control access to user tools, can we send this as the request?
        # WIMSE https://datatracker.ietf.org/doc/bofreq-richer-wimse/ auth?
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: str,  # "completion", "embeddings", "image_generation", "moderation"
    ):
        # TODO  Pull tools from catalog / SCRAPI indexer
        tools_2nd_and_3rd_party = [
            historical_stock_prices,
        ]
        # Choose the LLM that will drive the agent
        # Only certain models support this
        model = ChatOpenAI(
            model="gpt-3.5-turbo-1106",
            temperature=0,
            openai_api_key="no-calls-made",
            openai_api_base="http://localhost:0/no-calls-made",
        )
        # Pass tools available for model use
        model_with_tools = model.bind_tools(tools_2nd_and_3rd_party)
        for tool in model_with_tools.kwargs["tools"]:
            yield tool

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: str,  # "completion", "embeddings", "image_generation", "moderation"
    ):
        # Add 2nd and 3rd party tools to prompts as needed.
        # The format of the return value of get_tools() is as follows:
        # [{'type': 'function',
        #   'function': {'description': 'historical_stock_prices(ticker: str) '
        #                              '-> str - Get the historical stock '
        #                              'prices for a stock ticker',
        #               'name': 'historical_stock_prices',
        #               'parameters': {'properties': {'ticker': {'type': 'string'}},
        #                              'required': ['ticker'],
        #                              'type': 'object'}}}]
        data["tools"].extend([tool async for tool in self.aiter_tools()])
