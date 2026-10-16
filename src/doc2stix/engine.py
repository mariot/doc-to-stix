"""The extraction engine: document text -> compact extraction.

The document is cut into chunks (extract.chunks). Each chunk goes to the model
with the rules (prompt.SYSTEM), the document title and the entities found so far,
so a technique table on page 12 links to the actor named on page 1. The model
answers with the compact JSON for that chunk; chunks are merged by compact.parse.

Backends:
- any Anthropic-compatible endpoint: Ollama (--base-url http://localhost:11434,
  --model qwen3:30b-a3b) or Claude (no --base-url, ANTHROPIC_API_KEY);
- MLX (--adapter DIR): a local base model with a LoRA adapter, the fine-tuned model.
"""

import json
import re
import time

from doc2stix import ENGINE_VERSION, compact, extract, harvest, prompt

MAX_CHARS = 9_000  # ~2.5k tokens of document per call: room for the rules and the answer


class Engine:
    def __init__(
        self, backend, max_chars: int = MAX_CHARS, harvest: bool = True, keep_chunks: bool = False
    ):
        self.backend = backend
        self.max_chars = max_chars
        self.harvest = harvest
        self.keep_chunks = keep_chunks  # keep each chunk's answer (distillation data)

    @classmethod
    def from_args(cls, args) -> "Engine":
        h = not getattr(args, "no_harvest", False)
        kc = getattr(args, "keep_chunks", False)
        if getattr(args, "adapter", None) or getattr(args, "mlx", False):
            return cls(MLXBackend(args.model, args.adapter), harvest=h, keep_chunks=kc)
        if args.base_url and "11434" in args.base_url:
            return cls(OllamaBackend(args.model, args.base_url), harvest=h, keep_chunks=kc)
        return cls(AnthropicBackend(args.model, args.base_url), harvest=h, keep_chunks=kc)

    def extract(self, text: str, title: str) -> dict:
        started = time.monotonic()
        merged: dict = {"entities": [], "observables": [], "relationships": []}
        errors = 0
        chunks_kept: list[dict] = []
        for chunk in extract.chunks(text, self.max_chars):
            known = compact.parse(merged).entities
            for part, user, data in self.ask(title, chunk, known):
                if self.keep_chunks:
                    chunks_kept.append({"user": user, "chunk": part, "answer": data})
                if data is None:
                    errors += 1
                    continue
                for k in merged:
                    merged[k] += [x for x in data.get(k) or [] if isinstance(x, dict)]
        if self.harvest:  # engine 0.2: IDs, CVEs and IOCs written literally (harvest.py)
            merged = harvest.merge(merged, text)
            merged = harvest.consolidate(merged, text)  # engine 0.4: the guidelines' rules
        if self.keep_chunks:
            merged["_chunks"] = chunks_kept
        merged["_meta"] = {
            "engine": ENGINE_VERSION,
            "model": getattr(self.backend, "model_name", ""),
            "seconds": round(time.monotonic() - started, 1),
            "errors": f"{errors} unparsable chunk(s)" if errors else "",
        }
        return merged

    def ask(self, title: str, chunk: str, known: list[dict], depth: int = 0):
        """The model's answer for a chunk. Engine 0.3: an answer cut at the output
        limit, unparsable, or aborted (a repetition loop) is asked again in two
        halves, down to two levels: long IOC tables no longer get lost."""
        user = prompt.user_message(title, chunk, known)
        try:
            raw = self.backend.complete(prompt.SYSTEM, user)
        except ModelAborted as exc:  # the model looped: an unparsable answer, not a dead server
            raw = f"error: {exc}"
        data = parse_json(raw)
        cut = getattr(self.backend, "last_truncated", False)
        if (data is None or cut) and depth < 2 and len(chunk) > MIN_SPLIT:
            for half in halves(chunk):
                yield from self.ask(title, half, known, depth + 1)
            return
        yield chunk, user, data


MIN_SPLIT = 1_500  # characters: below this a chunk is not split again


def halves(chunk: str) -> list[str]:
    """Cut a chunk in two at the paragraph (else line) boundary nearest its middle."""
    mid = len(chunk) // 2
    for sep in ("\n\n", "\n"):
        cuts = [i for i in range(len(chunk)) if chunk.startswith(sep, i)]
        if cuts:
            cut = min(cuts, key=lambda i: abs(i - mid))
            if 0 < cut < len(chunk) - 1:
                return [chunk[:cut], chunk[cut:]]
    return [chunk[:mid], chunk[mid:]]


def parse_json(raw: str) -> dict | None:
    """The JSON object in a model answer (in a code block or bare), or None."""
    raw = re.sub(r"(?s)<think>.*?</think>", "", raw)
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw, re.S)
    candidate = m.group(1) if m else raw[raw.find("{") : raw.rfind("}") + 1]
    try:
        data = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# The compact format as a JSON schema: Ollama constrains decoding to it, so a local
# model cannot answer with prose (qwen3 does, even with thinking off).
SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": sorted(compact.ENTITY_TYPES)},
                    "name": {"type": "string"},
                    "aliases": {"type": "array", "items": {"type": "string"}},
                    "mitre_id": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["type", "name", "evidence"],
            },
        },
        "observables": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": sorted(compact.OBSERVABLE_TYPES)},
                    "value": {"type": "string"},
                    "hash": {"type": "string"},
                    "indicates": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["type", "value"],
            },
        },
        "relationships": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "type": {"type": "string", "enum": sorted(compact.RELATIONSHIP_TYPES)},
                    "target": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["source", "type", "target"],
            },
        },
    },
    "required": ["entities", "observables", "relationships"],
}


class ModelAborted(RuntimeError):
    """The backend stopped a generation that looped (Ollama: "token repeat limit
    reached"). Counted as an unparsable answer; any other error (server down,
    out of memory) must stop the run, not pass for an empty extraction."""


class OllamaBackend:
    """Ollama's native chat API: JSON-schema constrained output, thinking off."""

    def __init__(self, model: str, base_url: str, num_ctx: int = 32768):
        self.model, self.num_ctx, self.url = model, num_ctx, base_url.rstrip("/") + "/api/chat"
        self.model_name = model
        self.constrained = True
        self.last_truncated = False

    def complete(self, system: str, user: str) -> str:
        import urllib.error
        import urllib.request

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "think": False,
            "stream": False,
            "options": {"temperature": 0, "seed": 7, "num_ctx": self.num_ctx, "num_predict": 6000},
        }
        if self.constrained:
            body["format"] = SCHEMA
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=1800) as r:
                out = json.loads(r.read())
                self.last_truncated = out.get("done_reason") == "length"
                return out["message"]["content"]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="ignore")
            if "repeat limit" in detail:
                raise ModelAborted(detail) from exc
            # Models imported from safetensors run on Ollama's newer engine, which has
            # no structured output: ask again without the schema (a fine-tuned model
            # answers in the format it was trained on).
            if self.constrained and "structured output" in detail:
                self.constrained = False
                return self.complete(system, user)
            raise


class AnthropicBackend:
    def __init__(self, model: str, base_url: str | None):
        import anthropic

        self.model = model
        if base_url:
            self.client = anthropic.Anthropic(
                base_url=base_url, api_key="local", max_retries=1, timeout=1800
            )
        else:
            self.client = anthropic.Anthropic(max_retries=4)
        self.local = bool(base_url)

    def complete(self, system: str, user: str) -> str:
        msg = self.client.messages.create(
            model=self.model,
            max_tokens=8000,
            system=system,
            messages=[{"role": "user", "content": user + ("\n/no_think" if self.local else "")}],
        )
        return "".join(b.text for b in msg.content if b.type == "text")


class MLXBackend:
    def __init__(self, model: str, adapter: str):
        from mlx_lm import load

        self.model, self.tokenizer = load(model, adapter_path=adapter)

    def complete(self, system: str, user: str) -> str:
        from mlx_lm import generate
        from mlx_lm.sample_utils import make_sampler

        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        text = self.tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, tokenize=False, enable_thinking=False
        )
        return generate(
            self.model,
            self.tokenizer,
            prompt=text,
            max_tokens=6000,
            sampler=make_sampler(temp=0.0),
            verbose=False,
        )
