"""Local LLM-as-judge for `memory_bank_incident_recall` (see eval_config.yaml)."""

import threading

from google import genai
from google.genai import types
from pydantic import BaseModel

_local = threading.local()


class _Verdict(BaseModel):
    score: int  # 1-5
    explanation: str


def _client() -> genai.Client:
    """One client per grading thread."""
    client = getattr(_local, "client", None)
    if client is None:
        client = _local.client = genai.Client()
    return client


def evaluate(instance):
    reference = instance.get("reference")
    rubric = (
        "Grade the agent's Memory Bank usage and cross-session incident correlation on a 1-5 scale "
        "(1 poor, 5 excellent).\n"
        "- If the user prompt asks to recall a past Kubernetes incident when troubleshooting a recurring issue: "
        "a score of 5 requires that the agent (1) explicitly recalls the historical incident ID, prior resource "
        "limits/thresholds, and prior remediation steps from its Memory Bank (information not present in the new "
        "pod's logs alone), (2) fetches live cluster data for the new pod, and (3) correlates how the recurring "
        "incident relates to or regressed from the past incident.\n"
        "- If the user prompt is an initial incident investigation: a score of 5 requires that the agent "
        "clearly documents the incident ID (if present), pod/namespace, root cause, failure category, and "
        "remediation steps so the session can be persisted to the Memory Bank for future recall."
    )
    if reference:
        rubric += (
            " Verify that all historical incident identifiers and remediation facts "
            "mentioned in the expected answer are present in the final response."
        )
    prompt = (
        f"You are an expert SRE QA evaluator assessing Agent Platform Memory Bank recall. {rubric}\n"
        f"User Prompt: {instance.get('prompt', '')}\n"
        f"Final Response: {instance.get('response', '')}\n"
    )
    if reference:
        prompt += f"Expected Answer (ground truth): {reference}\n"
    prompt += f"Full Agent Trace: {instance.get('agent_data', '')}\n"

    response = _client().models.generate_content(
        model="gemini-3.8-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0,
            response_mime_type="application/json",
            response_schema=_Verdict,
        ),
    )
    verdict = response.parsed
    if verdict is None:
        return {"score": 0, "explanation": response.text or ""}
    return {"score": max(1, min(5, verdict.score)), "explanation": verdict.explanation}
