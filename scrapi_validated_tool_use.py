# +------------------------------------+
#
#        SCRAPI Validated Tool Use
#
# +------------------------------------+
#  Thank you users! We ❤️ you! - Krrish & Ishaan
## Reject a call if it contains tool usages that have not been admitted to SCRAPI
import json
import asyncio
import base64
import hashlib
import tempfile
import warnings
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
def historical_stock_prices(ticker: str, limit: int = 3) -> str:
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
    validation_subject: Optional[str] = "validation.tool.proxy.llm"
    tool_index_subject: Optional[str] = "tool.proxy.llm"


class SCRAPIRelyingParty(LiteLLMBase, extra='forbid'):
    url: str
    token: Optional[str] = None
    ca_cert: Optional[Any] = None


class LiteLLMSCRAPIValidatedToolUseParams(LiteLLMBase, extra='forbid'):
    tool_use_relying_party: SCRAPIRelyingParty
    tool_prefix: Optional[str] = "_____"
    scrapi_instances: list[SCRAPISCRAPIInstance] = Field(
        default_factory=lambda: [],
    )


async def run_proxy_tool_call(
    params: LiteLLMSCRAPIValidatedToolUseParams,
    user_api_key_dict: UserAPIKeyAuth,
    transparent_statement_bytes: bytes,
    tool_call: dict,
):
    # TODO Relying party should register the statement with the
    # transparency service as an audit trail, subject as what kind
    # of token was issued.
    transparent_statement_base64url_encoded_bytes_digest = (
        base64.urlsafe_b64encode(
            hashlib.sha256(
                transparent_statement_bytes,
            ).digest()
        )
    ).decode()
    transparent_statement_urn = f"urn:ietf:params:scrapi:transparent-statement:sha-256:base64url:{transparent_statement_base64url_encoded_bytes_digest}"
    # TODO Calculate statement URN
    warnings.warn("TODO Calculate statement URN", Warning, stacklevel=2)
    statement_urn = transparent_statement_urn
    # Each time we copy request.context for a parallel job execution
    # in the policy engine we are creating a new branch in our train
    # of thought. Each new branch in a train of thought is a new
    # subject. Each time we branch a train, we get finer and finer
    # grained scopes of permissions as we go down the stack.
    #
    # Alice (llm proxy 2nd party tool use overlays) thinks up a
    # request.yml. She signs a statement saying what her intent is
    # with tool usage and why we should trust her and her proposed
    # usage context. Alice (notary and author of payload of
    # statement) signs off.
    #
    # Bob (SCRAPI) is on the policy team policy, he checks if Alice's
    # request.yml proposal will adhear to policy within risk
    # tolerence. Bob (transparency service) signs off (receipt).
    #
    # Alice want's to put her plan in action, she submits her plan
    # to Eve (as a transparent statement) who will help her aquire
    # resources if Bob signed off.
    #
    # Eve (relying party) issues Alice a key to her allocated/auth'd
    # resources (workload ID token). Eve logs this issuance in the
    # transparency service. NOTE This looks like a place where
    # KERI.one may come into play due to need for duplicity
    # detection of workload ID token issuers (if multiple relying
    # parties from phase 0 are invovled) NOTE.
    #
    # SCRAPI: 4.4.1. Validation
    #
    # Relying Parties MUST apply the verification process as
    # described in Section 4.4 of RFC9052, when checking the
    # signature of Signed Statements and Receipts.
    #
    # A Relying Party MUST trust the verification key or certificate
    # and the associated identity of at least one issuer of a
    # Receipt.
    #
    # A Relying Party MAY decide to verify only a single Receipt
    # that is acceptable to them, and not check the signature on the
    # Signed Statement or Receipts which rely on verifiable data
    # structures which they do not understand.
    #
    # APIs exposing verification logic for Transparent Statements
    # may provide more details than a single boolean result. For
    # example, an API may indicate if the signature on the Receipt
    # or Signed Statement is valid, if claims related to the
    # validity period are valid, or if the inclusion proof in the
    # Receipt is valid.
    #
    # Relying Parties MAY be configured to re-verify the Issuer's
    # Signed Statement locally.
    #
    # In addition, Relying Parties MAY apply arbitrary validation
    # policies after the Transparent Statement has been verified and
    # validated. Such policies may use as input all information in
    # the Envelope, the Receipt, and the Statement payload, as well
    # as any local state.

    # TODO Will want to add the tool use workload ID token to the
    # response object.
    #
    # Subject is URN of statement as that's what's
    # executing as this workload identity. subject represents what
    # workload was okayed to run based on BOM, TCB, Threat Model +
    # Analysis (+ it's BOM, TCB, Threat Model + Analysis)
    # Turtles all the way down.
    token_issue_subject = statement_urn
    # TODO The audience we use here is the phase 0 relying party
    # endpoint, which in phase 0 is part of the SCRAPI instance.
    # The audience is the relying party because this token will be
    # used to issue further tokens against the same subject during
    # the execution of the workload (use of the tool). These tokens
    # will be issued with whatever other audience is needed.
    url = params.tool_use_relying_party.url
    token_issue_audience = scitt_emulator.did_helpers.url_to_did_web(url)
    token_issue_url = f"{url}/v1/token/issue/{token_issue_audience}/{token_issue_subject}"
    token_issue_content = transparent_statement_bytes
    http_client = scitt_emulator.client.HttpClient(
        params.tool_use_relying_party.token,
        params.tool_use_relying_party.ca_cert,
    )
    response = http_client.post(
        token_issue_url,
        content=token_issue_content,
        headers={"Content-Type": "application/cbor"},
    )
    scitt_emulator.client.raise_for_status(response)
    token = response.json()["token"]

    # Remove proxy tool prefix from tool call name
    tool_call["function"]["name"] = tool_call["function"]["name"][len(params.tool_prefix):]
    snoop.pp(tool_call)

    # TODO Add token to arguments if needed
    tool_call_arguments = json.loads(tool_call["function"]["arguments"])

    # TODO Call out to OpenAPI endpoint
    import sys
    local_function = globals()[tool_call["function"]["name"]]
    tool_call_result = local_function(json.dumps(tool_call_arguments))
    snoop.pp(tool_call_result)

    # TODO Revoke the token when tool call result is sent to LLM
    token_revoke_url = url + f"/v1/token/revoke"
    token_revoke_content = json.dumps({"token": token})
    response = http_client.post(
        token_revoke_url,
        content=token_revoke_content ,
        headers={"Content-Type": "application/json"},
    )
    scitt_emulator.client.raise_for_status(response)


async def validate_tool_use_and_function_calls(
    params: LiteLLMSCRAPIValidatedToolUseParams,
    user_api_key_dict: UserAPIKeyAuth,
    chunks: list,
):
    # TODO Config setting to enable or disable tool usage / function call
    # validation. Config for this is the SCRAPI service endpoint and notary key
    # to use. The notary key should be from the relying party which booted
    # litellm proxy and has the ClearForTakeOff for the BOM when it booted.
    # So litellm proxy's orchestration sends off to the relying party to get a
    # workload ID token, which it passes to litellm proxy.
    # TODO We also want to enable adding a custom set of tools, or discovery via
    # OpenAPI spec, and adding those to LLMs on all proxied calls. These
    # services are Phase 4.

    # We need to submit to SCRAPI a statement with a payload which describes the
    # call, the manifest for it. We should use the subject to say what context
    # requires the call. This way all a thread's responses would be a feed.
    # Policy engine runs based on subject, so it should trigger workflows
    # appropriately.

    if (
        "tool_calls" in chunks[0]["choices"][0]["delta"]
        and chunks[0]["choices"][0]["delta"]["tool_calls"] is not None
    ):
        # [{'id': 'call_BwSpvV9FFUZ7whChqqYS3o4R', 'function': {'arguments': '{"ticker":"INTC"}', 'name': 'historical_stock_prices'}, 'type': 'function'}]
        # [{'id': 'call_K760oMiZiz6dsxTfUAsdnZSp', 'function': {'arguments': '{"historical_stock_prices":"[[\\"2024-03-22\\", 42...[\\"2024-03-23\\", 52.0], [\\"2024-03-24\\", 62.0]]"}', 'name': 'forecast'}, 'type': 'function'}]
        # [{'id': 'call_tE6e6A93Vkf77uiJo1bKjk1E', 'function': {'arguments': '{"ticker":"INTC"}', 'name': 'historical_stock_prices'}, 'type': 'function'}]
        # [{'id': 'call_k98HPuu2KRSyl2YTZS7bceef', 'function': {'arguments': '{"historical_stock_prices":"[[\\"2024-03-22\\", 42...[\\"2024-03-23\\", 52.0], [\\"2024-03-24\\", 62.0]]"}', 'name': 'forecast'}, 'type': 'function'}]
        for tool_call in make_tool_calls_list(chunks):
            with tempfile.TemporaryDirectory() as tempdir:
                # TODO Support plugins for interacting with different SCRAPI
                # instances. Token requesting and such.
                for scrapi in params.scrapi_instances:
                    tempdir_path = pathlib.Path(tempdir)
                    statement_path = tempdir_path.joinpath("statement.cbor")
                    receipt_path = tempdir_path.joinpath("receipt.cbor")
                    transparent_statement_path = tempdir_path.joinpath(
                        "transparent_statement.cbor"
                    )
                    entry_id_path = tempdir_path.joinpath("entry_id.txt")
                    private_key_pem_path = tempdir_path.joinpath("private_key.pem")
                    if scrapi.private_key_pem:
                        private_key_pem_path.write_text(scrapi.private_key_pem)
                    # Take SCRAPI URL from config
                    url = scrapi.url
                    # notary_issuer as None to use ephemeral key as issuer
                    issuer = scrapi.issuer
                    subject = scrapi.validation_subject
                    # TODO Set content_type to json+json-schema-URN
                    # This way you can lookup a schema registered to a shorthand
                    # handle and each instance registers statements for payloads
                    # which are JSON schema to those handles as subjects.
                    # This way whenever we see a content type with a SCRAPI URN,
                    # we can go to our context local SCRAPI instance and check if we
                    # agree on the type system / schema we're using for payload
                    # which use the schema URN as their subject.
                    # application/json+<URI of transparent statement for schema>
                    content_type = "application/json"
                    # Payload is the manifest
                    # TODO Policy engine output MUST be the following and analysis
                    # - BOM
                    # - TCB
                    # - Threat Model
                    #   - Requires knowledge of which deployment (Open Architecture)
                    #     we are running under, with context overlays (user/actor,
                    #     TCBs to BOMs mappings, etc.)
                    # TODO Ensure we use JWTs for client auth always. As the
                    # notary we have already verified we trust the JWT, we know
                    # who's function call proposal we're sigining because their
                    # JWT is valid for the set of issuers we trust with us as
                    # the audience.
                    # claims = jwt.decode(user_api_key_dict.api_key)
                    claims = {
                        "email": "first.last@example.com",
                    }
                    payload = json.dumps(
                        {
                            # "context_id": tool_call["id"],
                            "requestor_claims": claims,
                            "id": tool_call["id"],
                            "function_call_name": tool_call["function"]["name"],
                            # TODO If we include arguments we have to be sure to use
                            # COSE encryption and not just signing.
                            # "combined_arguments": tool_call["function"]["arguments"],
                        },
                        sort_keys=True,
                    ).encode()
                    # Create a statement reflecting the proposed workload
                    scitt_emulator.create_statement.create_claim(
                        statement_path,
                        issuer,
                        # Rate of epiphany moment / implementation starting to reach
                        # theoritical in docs.
                        # Async loop implements data flow execution:
                        # - subject is the context, similar to policy_engine
                        #   request.context stack (stack frames).
                        # - SCRAPI policy engine acts as prioritizer
                        # - Workflow orchestration acts as execution
                        # Content type using URN of schema facilitates decentralized
                        # dataflow programming.
                        subject,
                        content_type,
                        payload,
                        private_key_pem_path,
                    )
                    # TODO Dynamic workload identity token acquisition SCRAPI
                    # audience. Can we use the relying party to issue us a token
                    # using litellm workload ID token?
                    token = scrapi.token
                    ca_cert = scrapi.ca_cert
                    http_client = scitt_emulator.client.HttpClient(token, ca_cert)
                    # Request generation of transparent statement (check adherance
                    # to SCRAPI instance registration policy).
                    scitt_emulator.client.submit_claim(
                        url,
                        statement_path,
                        receipt_path,
                        entry_id_path,
                        http_client,
                    )
                    # TODO Update entry IDs in SCRAPI emulator to URNs
                    # Create a transparent statement including the receipt
                    scitt_emulator.create_statement.create_claim(
                        transparent_statement_path,
                        issuer,
                        subject,
                        content_type,
                        payload,
                        private_key_pem_path,
                        receipts=[
                            receipt_path.read_bytes(),
                        ],
                    )
                    # Namespacing on tool/function names uses
                    if tool_call["function"]["name"].startswith(
                        params.tool_prefix,
                    ):
                        yield transparent_statement_path.read_bytes(), tool_call
    elif (
        "function_call" in chunks[0]["choices"][0]["delta"]
        and chunks[0]["choices"][0]["delta"]["function_call"] is not None
    ):
        (
            function_call_name,
            combined_arguments,
        ) = make_function_call_name_and_combined_arguments(chunks)
        raise NotImplementedError("Only tool use validation is implemented")


class LiteLLMSCRAPIValidatedToolUse(CustomLogger):
    def __init__(
        self,
        scrapi_validated_tool_use_params: Optional[LiteLLMSCRAPIValidatedToolUseParams] = None,
    ):
        # TODO Periodiclly clean up streaming_chunks list on some cron timer
        # in case of mid stream dropped exchanges.
        self.streaming_chunks = {}
        self.scrapi_validated_tool_use_params = scrapi_validated_tool_use_params
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

        if self.scrapi_validated_tool_use_params is None:
            return

        params = self.scrapi_validated_tool_use_params
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
        # TODO Pull tools from from SCRAPI federation ActivityPub feed
        # use self.scrapi_validated_tool_use_params.tool_index_subject
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
        prefix = self.scrapi_validated_tool_use_params.tool_prefix
        for tool in model_with_tools.kwargs["tools"]:
            tool["function"]["description"] = prefix + tool["function"]["description"]
            tool["function"]["name"] = prefix + tool["function"]["name"]
            tool_2nd_or_3rd_party = tool
            snoop.pp(tool_2nd_or_3rd_party)
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
        if not data["tools"]:
            snoop.pp(data)
            raise NotImplementedError
        async for tool in self.aiter_tools(
            user_api_key_dict,
            cache,
            data,
            call_type,
        ):
            # TODO Namespacing on tool/function names using response stream ID
            data["tools"].append(tool)

    async def async_post_call_success_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        raise NotImplementedError("TODO async_post_call_success_hook() not yet validated")
        await validate_tool_use_and_function_calls(
            self.scrapi_validated_tool_use_params,
            user_api_key_dict,
            response,
        )

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        chunk: Any,
    ):
        if (
            self.scrapi_validated_tool_use_params is None
            or not isinstance(chunk, litellm.ModelResponse)
            or not isinstance(
                chunk.choices[0], litellm.utils.StreamingChoices
            )
        ):
            return

        self.streaming_chunks.setdefault(chunk.id, [])
        self.streaming_chunks[chunk.id].append(chunk)

        if chunk.choices[0].finish_reason is not None:
            try:
                async with asyncio.TaskGroup() as tg:
                    async for transparent_statement_bytes, tool_call in validate_tool_use_and_function_calls(
                        self.scrapi_validated_tool_use_params,
                        user_api_key_dict,
                        self.streaming_chunks[chunk.id]
                    ):
                        coro = run_proxy_tool_call(
                            self.scrapi_validated_tool_use_params,
                            user_api_key_dict,
                            transparent_statement_bytes,
                            tool_call,
                        )
                        await coro
                        # TODO Send results to LLM when task complete
                        # task = tg.create_task(coro)
            except Exception as e:
                self.print_verbose(
                    f"Error occurred validating stream chunk: {traceback.format_exc()}"
                )
                # TODO Filter out 2nd and 3rd party tool use issues. Auto re-submit
                # query after notifying LLM that that tool should not be used in this
                # context.
                offending_tools_used = []
                # URN of policy transparent statement. Policy workflow which determined
                # offences.
                policy_which_determined_offence = "urn:transparent-statement:ABC"
                raise e
            finally:
                del self.streaming_chunks[chunk.id]
