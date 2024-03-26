# +------------------------------------+
#
#        SCITT Validated Tool Use
#
# +------------------------------------+
#  Thank you users! We ❤️ you! - Krrish & Ishaan
## Reject a call if it contains tool usages that have not been admitted to SCITT


from typing import Optional, Literal
from pydantic import Field
import litellm
from litellm.caching import DualCache
from litellm.proxy._types import UserAPIKeyAuth, LiteLLMBase
from litellm.integrations.custom_logger import CustomLogger
from litellm._logging import verbose_proxy_logger
from litellm.utils import get_formatted_prompt
from fastapi import HTTPException
import json, traceback, re
from difflib import SequenceMatcher
from typing import List

import httpx
import scitt_emulator.create_statement
import scitt_emulator.client

import snoop


def create_transparent_statement(
    statement_path,
    receipt_path,
    transparent_statement_path,
    private_key_pem_path,
):
    # TODO
    transparent_statement_path.write_bytes(receipt_path.read_bytes())


@snoop
def validate_tool_use_and_function_calls(
    self, chunks: list, messages: Optional[list] = None, start_time=None, end_time=None
):
    # TODO Config setting to enable or disable tool usage / function call
    # validation. Config for this is the SCITT service endpoint and notary key
    # to use. The notary key should be from the relying party which booted
    # litellm proxy and has the ClearForTakeOff for the BOM when it booted.
    # So litellm proxy's orchestration sends off to the relying party to get a
    # workload ID token, which it passes to litellm proxy.
    # TODO We also want to enable adding a custom set of tools, or discovery via
    # OpenAPI spec, and adding those to LLMs on all proxied calls. These
    # services are Phase 4.
    import snoop

    snoop.pp(locals())

    # We need to submit to SCITT a statement with a payload which describes the
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
                tempdir_path = pathlib.Path(tempdir)
                statement_path = tempdir_path.joinpath("statement.cbor")
                receipt_path = tempdir_path.joinpath("receipt.cbor")
                transparent_statement_path = tempdir_path.joinpath(
                    "transparent_statement.cbor"
                )
                entry_id_path = tempdir_path.joinpath("entry_id.txt")
                private_key_pem_path = tempdir_path.joinpath("private_key.pem")
                # TODO Take SCITT URL from config
                url = "https://scitt.unstable.chadig.com"
                # Use ephemeral key as issuer
                issuer = None
                # TODO subject should be the URN of the transparent statement
                # which is the schema for the manifest. We'll shorthand that to
                # an identifier until we setup that flow and discovery via
                # json-ld and pydantic schema dump.
                subject = "validate_tool_use_and_function_calls.proxy.llm"
                # TODO Set content_type to json+json-schema-URN
                # This way you can lookup a schema registered to a shorthand
                # handle and each instance registers statements for payloads
                # which are JSON schema to those handles as subjects.
                # This way whenever we see a content type with a SCITT URN,
                # we can go to our context local SCITT instance and check if we
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
                payload = json.dumps(
                    {
                        # "context_id": tool_call["id"],
                        "id": tool_call["id"],
                        "function_call_name": tool_call["function"]["name"],
                        # TODO If we include arguments we have to be sure to use
                        # COSE encryption and not just signing.
                        # "combined_arguments": tool_call["function"]["arguments"],
                    },
                    sort_keys=True,
                ).encode()
                # TODO Set from workload identity token with SCITT as audience
                token = None
                # TODO Set from config
                ca_cert = None
                http_client = scitt_emulator.client.HttpClient(token, ca_cert)
                # Create a statement reflecting the proposed workload
                scitt_emulator.create_statement.create_claim(
                    statement_path,
                    issuer,
                    # Rate of epiphany moment / implementation starting to reach
                    # theoritical in docs.
                    # Async loop implements data flow execution:
                    # - subject is the context, similar to policy_engine
                    #   request.context stack (stack frames).
                    # - SCITT policy engine acts as prioritizer
                    # - Workflow orchestration acts as execution
                    # Content type using URN of schema facilitates decentralized
                    # dataflow programming.
                    subject,
                    content_type,
                    payload,
                    private_key_pem_path,
                )
                # Request generation of transparent statement (check adherance
                # to SCITT instance registration policy).
                scitt_emulator.client.submit_claim(
                    url,
                    statement_path,
                    receipt_path,
                    entry_id_path,
                    http_client,
                )
                # TODO Update entry IDs in SCITT emulator to URNs
                # TODO scitt_emulator.create_transparent_statement.create_transparent_statement(
                create_transparent_statement(
                    statement_path,
                    receipt_path,
                    transparent_statement_path,
                    private_key_pem_path,
                )
                # Call it here and calculate the URN.
                # TODO Relying party should register the statement with the
                # transparency service as an audit trail, subject as what kind
                # of token was issued.
                transparent_statement_urn = entry_id_path.read_text()
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
                # Bob (SCITT) is on the policy team policy, he checks if Alice's
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
                # SCITT: 4.4.1. Validation
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
                # Subject is URN of transparent statement as that's what's
                # executing as this workload identity. subject represents what
                # workload was okayed to run based on BOM, TCB, Threat Model +
                # Analysis (+ it's BOM, TCB, Threat Model + Analysis)
                # Turtles all the way down.
                token_issue_subject = transparent_statement_urn
                # TODO The audience we use here is the phase 0 relying party
                # endpoint, which in phase 0 is part of the SCITT instance.
                # The audience is the relying party because this token will be
                # used to issue further tokens against the same subject during
                # the execution of the workload (use of the tool). These tokens
                # will be issued with whatever other audience is needed.
                token_issue_audience = url
                token_issue_url + f"{url}/v1/token/issue/{token_issue_audience}/{token_issue_subject}"
                token_issue_content = transparent_statement_path.read_bytes()
                # response = http_client.post(
                #     token_issue_url,
                #     content=token_issue_content,
                #     headers={"Content-Type": "application/cbor"},
                # )
                # scitt_emulator.client.raise_for_status(response)
                # token = response.json()["token"]
                # TODO Enforce namespacing on tool/function names.
                # TODO Call overlayed 2nd party tools and pass them their
                # tokens. Somehow analyize langchain prompts similar to how we
                # will append tools and get their arguments / inspect.signature
                # type of thing. Ideally pass those by inference of which
                # argument (by name or data type) their JWT.
                # TODO Revoke the token when we intercept a return value
                # token_revoke_url = url + f"/v1/token/revoke"
                # token_revoke_content = json.dumps({"token": token})
                # response = http_client.post(
                #     token_revoke_url,
                #     content=token_revoke_content ,
                #     headers={"Content-Type": "application/cbor"},
                # )
                # scitt_emulator.client.raise_for_status(response)
    elif (
        "function_call" in chunks[0]["choices"][0]["delta"]
        and chunks[0]["choices"][0]["delta"]["function_call"] is not None
    ):
        (
            function_call_name,
            combined_arguments,
        ) = make_function_call_name_and_combined_arguments(chunks)
        raise NotImplementedError("Only tool use validation is implemented")


class LiteLLMSCITTValidatedToolUseParams(LiteLLMBase):
    scrapi_instance_urls: list[str] = Field(
        default_factory=lambda: [],
    )


class LiteLLMSCITTValidatedToolUse(CustomLogger):
    def __init__(
        self,
        scitt_validated_tool_use_params: Optional[LiteLLMSCITTValidatedToolUseParams] = None,
    ):
        self.scitt_validated_tool_use_params = scitt_validated_tool_use_params
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

        if self.scitt_validated_tool_use_params is not None:
            # TODO Validate parameters
            self.print_verbose(
                f"params: {self.scitt_validated_tool_use_params}"
            )

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: str,  # "completion", "embeddings", "image_generation", "moderation"
    ):
        # TODO Add 2nd and 3rd party tools to prompts as needed
        pass

    async def async_post_call_success_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        self.print_verbose(
            f"IN POST CALL SUCCESS HOOK - self.scitt_validated_tool_use_params = {self.scitt_validated_tool_use_params}"
        )
        snoop.pp(user_api_key_dict)
        snoop.pp(response)

        if self.scitt_validated_tool_use_params is None:
            return

        return
        if isinstance(response, litellm.ModelResponse) and isinstance(
            response.choices[0], litellm.utils.Choices
        ):
            pass

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: str,
    ):
        raise HTTPException(
            status_code=400,
            # TODO Encode error into output.
            detail={"error": f"Agent's tool use does not align with policy."},
        )
        snoop.pp(user_api_key_dict)
        snoop.pp(response)
        self.print_verbose(
            f"IN ASYNC MODERATION HOOK - self.scitt_validated_tool_use_params = {self.scitt_validated_tool_use_params}"
        )
        if self.scitt_validated_tool_use_params is None:
            return

        return

        try:
            validate_tool_use_and_function_calls(
                self,
                self.streaming_chunks,
                messages=self.model_call_details.get("messages", None),
                start_time=start_time,
                end_time=end_time,
            )
        except Exception as e:
            verbose_logger.debug(
                f"Error occurred validating stream chunk: {traceback.format_exc()}"
            )
            complete_streaming_response = None


        formatted_prompt = get_formatted_prompt(data=data, call_type=call_type)  # type: ignore
        is_prompt_attack = False

        scitt_validated_tool_use_system_prompt = getattr(
            self.scitt_validated_tool_use_params,
            "llm_api_system_prompt",
            scitt_validated_tool_use_detection_default_pt(),
        )

        # 3. check if llm api check turned on
        if (
            self.scitt_validated_tool_use_params.llm_api_check == True
            and self.scitt_validated_tool_use_params.llm_api_name is not None
            and self.llm_router is not None
        ):
            # make a call to the llm api
            response = await self.llm_router.acompletion(
                model=self.scitt_validated_tool_use_params.llm_api_name,
                messages=[
                    {
                        "role": "system",
                        "content": scitt_validated_tool_use_system_prompt,
                    },
                    {"role": "user", "content": formatted_prompt},
                ],
            )

            self.print_verbose(f"Received LLM Moderation response: {response}")
            self.print_verbose(
                f"llm_api_fail_call_string: {self.scitt_validated_tool_use_params.llm_api_fail_call_string}"
            )
            if isinstance(response, litellm.ModelResponse) and isinstance(
                response.choices[0], litellm.Choices
            ):
                if self.scitt_validated_tool_use_params.llm_api_fail_call_string in response.choices[0].message.content:  # type: ignore
                    is_prompt_attack = True

        if is_prompt_attack == True:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Rejected message. Tool use does not align with policy."
                },
            )

        return is_prompt_attack
        # TODO Filter out 2nd and 3rd party tool use issues. Auto re-submit
        # query after notifying LLM that that tool should not be used in this
        # context.
        offending_tools_used = []
        # URN of policy transparent statement. Policy workflow which determined
        # offences.
        policy_which_determined_offence = "urn:transparent-statement:ABC"
        # TODO Validate chunks
        return
        raise HTTPException(
            status_code=400,
            # TODO Encode error into output.
            detail={"error": f"Agent's tool use does not align with policy."},
        )
