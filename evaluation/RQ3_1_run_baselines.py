#!/usr/bin/env python3
"""
RQ3.1 Baseline Runner — call multiple LLMs on SinkTrace-Bench prompts.

Prerequisites:
  1. Generate prompts first:
       python evaluation/RQ3_1_sinktrace_benchmark.py --generate

  2. Set API keys in environment (only keys for models you want to run):
       GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY

Usage:
  # Run all configured models
  python evaluation/RQ3_1_run_baselines.py

  # Run specific models only
  python evaluation/RQ3_1_run_baselines.py --models gemini-2.5-pro gpt-4.1

  # Resume (skip prompts that already have a prediction file entry)
  python evaluation/RQ3_1_run_baselines.py --resume

  # Dry-run: print first prompt for each model without calling APIs
  python evaluation/RQ3_1_run_baselines.py --dry-run --models gemini-2.5-flash

After running, evaluate with:
  python evaluation/RQ3_1_sinktrace_benchmark.py --evaluate --latex
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
EVAL_DIR = Path(__file__).resolve().parent
PROMPTS_DIR = EVAL_DIR / "prompts"
RESPONSES_DIR = EVAL_DIR / "responses"

# ---------------------------------------------------------------------------
# Model configurations
# ---------------------------------------------------------------------------
MODELS: Dict[str, Dict[str, Any]] = {
    # Gemini models (Google GenAI)
    "gemini-2.5-flash": {
        "provider": "gemini",
        "model_id": "gemini-2.5-flash-preview-04-17",
        "rpm_limit": 10,          # free tier: 10 RPM
        "batch_delay": 7.0,       # seconds between calls
    },
    "gemini-2.5-pro": {
        "provider": "gemini",
        "model_id": "gemini-2.5-pro-preview-03-25",
        "rpm_limit": 5,
        "batch_delay": 13.0,
    },
    # OpenAI models
    "gpt-4.1": {
        "provider": "openai",
        "model_id": "gpt-4.1",
        "rpm_limit": 500,
        "batch_delay": 0.15,
    },
    "gpt-4o": {
        "provider": "openai",
        "model_id": "gpt-4o",
        "rpm_limit": 500,
        "batch_delay": 0.15,
    },
    # Anthropic models
    "claude-sonnet-4-5": {
        "provider": "anthropic",
        "model_id": "claude-sonnet-4-5-20251001",
        "rpm_limit": 50,
        "batch_delay": 1.5,
    },
}


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def _parse_trigger_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract trigger JSON from model response text."""
    # Try direct JSON parse
    try:
        data = json.loads(text.strip())
        if isinstance(data, dict) and "trigger_function" in data:
            return data
    except (json.JSONDecodeError, ValueError):
        pass

    # Extract first JSON object from text (model often wraps in markdown)
    match = re.search(r'\{[^{}]*"trigger_function"[^{}]*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: extract JSON block from markdown code fences
    fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _normalize_prediction(raw: Dict[str, Any], sample_id: str) -> Dict[str, Any]:
    """Normalize a parsed trigger JSON into evaluation format."""
    func = str(raw.get("trigger_function") or "").strip()
    line_raw = raw.get("trigger_line")
    try:
        line = int(line_raw) if line_raw is not None else 0
    except (ValueError, TypeError):
        line = 0
    stmt = str(raw.get("trigger_statement") or "").strip()

    return {
        "id": sample_id,
        "pred_function": func,
        "pred_line": line,
        "pred_statement": stmt,
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Provider-specific callers
# ---------------------------------------------------------------------------
def _call_gemini(model_id: str, system: str, user: str, api_key: str) -> str:
    from google import genai as google_genai
    from google.genai import types as genai_types

    client = google_genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model_id,
        contents=user,
        config=genai_types.GenerateContentConfig(
            system_instruction=system,
            temperature=0.0,
        ),
    )
    return response.text


def _call_openai(model_id: str, system: str, user: str, api_key: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_id,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.0,
    )
    return response.choices[0].message.content or ""


def _call_anthropic(model_id: str, system: str, user: str, api_key: str) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model_id,
        max_tokens=512,
        temperature=0.0,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text if message.content else ""


def _call_model(model_name: str, config: Dict[str, Any], system: str, user: str) -> str:
    provider = config["provider"]
    model_id = config["model_id"]

    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise EnvironmentError("GEMINI_API_KEY not set")
        return _call_gemini(model_id, system, user, api_key)

    elif provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY not set")
        return _call_openai(model_id, system, user, api_key)

    elif provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise EnvironmentError("ANTHROPIC_API_KEY not set")
        return _call_anthropic(model_id, system, user, api_key)

    else:
        raise ValueError(f"Unknown provider: {provider}")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------
def load_prompts() -> List[Dict[str, Any]]:
    manifest_path = PROMPTS_DIR / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: Prompt manifest not found at {manifest_path}")
        print("Run: python evaluation/RQ3_1_sinktrace_benchmark.py --generate")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    prompts = []
    for entry in manifest:
        prompt_file = PROMPTS_DIR / entry["file"]
        if not prompt_file.exists():
            print(f"  WARN: Missing prompt file {prompt_file.name}, skipping")
            continue
        with open(prompt_file) as f:
            prompts.append(json.load(f))

    print(f"Loaded {len(prompts)} prompts from {PROMPTS_DIR}/")
    return prompts


def run_model(
    model_name: str,
    config: Dict[str, Any],
    prompts: List[Dict[str, Any]],
    resume: bool = False,
    dry_run: bool = False,
) -> None:
    out_dir = RESPONSES_DIR / model_name
    out_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = out_dir / "predictions.jsonl"

    # Load already-completed IDs for resume mode
    completed_ids: set = set()
    if resume and predictions_path.exists():
        with open(predictions_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        completed_ids.add(json.loads(line)["id"])
                    except (json.JSONDecodeError, KeyError):
                        pass
        if completed_ids:
            print(f"  Resuming: {len(completed_ids)} predictions already saved, skipping those.")

    pending = [p for p in prompts if p["id"] not in completed_ids]
    print(f"\n{'=' * 60}")
    print(f"  Model: {model_name}  ({config['model_id']})")
    print(f"  Pending: {len(pending)} / {len(prompts)} prompts")
    print(f"{'=' * 60}")

    if dry_run:
        if pending:
            sample = pending[0]
            print(f"\n[DRY RUN] Sample prompt for ID={sample['id']}:")
            print("--- SYSTEM ---")
            print(sample["system"][:300] + "..." if len(sample["system"]) > 300 else sample["system"])
            print("--- USER (first 400 chars) ---")
            print(sample["user"][:400] + "...")
        return

    batch_delay = config.get("batch_delay", 1.0)

    with open(predictions_path, "a") as out_f:
        for idx, prompt in enumerate(pending, 1):
            sample_id = prompt["id"]
            cve_id = prompt.get("cve_id", "")
            print(f"  [{idx:4d}/{len(pending)}] {sample_id} ({cve_id})", end="", flush=True)

            try:
                raw_response = _call_model(
                    model_name, config,
                    system=prompt["system"],
                    user=prompt["user"],
                )
                parsed = _parse_trigger_json(raw_response)
                if parsed:
                    prediction = _normalize_prediction(parsed, sample_id)
                    print(f" -> func={prediction['pred_function']!r} line={prediction['pred_line']}")
                else:
                    # Save a null prediction so we don't retry indefinitely
                    prediction = {
                        "id": sample_id,
                        "pred_function": "",
                        "pred_line": 0,
                        "pred_statement": "",
                        "raw_response": raw_response[:200],
                        "parse_error": True,
                    }
                    print(f" -> [parse failed] response[:80]={raw_response[:80]!r}")

                out_f.write(json.dumps(prediction) + "\n")
                out_f.flush()

            except EnvironmentError as e:
                print(f"\n  FATAL: {e}")
                print("  Set the required API key environment variable and re-run.")
                sys.exit(1)
            except Exception as e:
                print(f" -> [ERROR] {e}")
                # Save error entry so resume works correctly
                out_f.write(json.dumps({
                    "id": sample_id,
                    "pred_function": "",
                    "pred_line": 0,
                    "pred_statement": "",
                    "error": str(e),
                }) + "\n")
                out_f.flush()

            if idx < len(pending):
                time.sleep(batch_delay)

    print(f"\n  Saved predictions to {predictions_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RQ3.1 Baseline Runner — call LLMs on SinkTrace-Bench prompts"
    )
    parser.add_argument(
        "--models",
        nargs="+",
        choices=list(MODELS.keys()),
        default=list(MODELS.keys()),
        metavar="MODEL",
        help=f"Models to run. Choices: {list(MODELS.keys())}",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip prompts that already have a saved prediction",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print one sample prompt per model without calling any API",
    )
    args = parser.parse_args()

    prompts = load_prompts()
    if not prompts:
        print("No prompts found. Run: python evaluation/RQ3_1_sinktrace_benchmark.py --generate")
        sys.exit(1)

    for model_name in args.models:
        config = MODELS[model_name]
        run_model(model_name, config, prompts, resume=args.resume, dry_run=args.dry_run)

    print("\nDone. Evaluate results with:")
    print("  python evaluation/RQ3_1_sinktrace_benchmark.py --evaluate --latex")


if __name__ == "__main__":
    main()
