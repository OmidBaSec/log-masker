"""Checks for the provider abstraction, focused on the keyless local
(Ollama) provider. Run: python test_providers.py

Network calls are stubbed — no provider (local or cloud) is contacted.
"""

import json

from log_masker import providers


def check(name, cond):
    print(("PASS" if cond else "FAIL") + " - " + name)
    assert cond, name


class FakeResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status
        self.text = json.dumps(data)

    def json(self):
        return self._data


def test_registry():
    check("ollama registered", "ollama" in providers.PROVIDERS)
    check("ollama is keyless", not providers.needs_key("ollama"))
    check("oauth provider is keyless too", not providers.needs_key("m365copilot"))
    check("cloud providers still need keys",
          all(providers.needs_key(p)
              for p in ("anthropic", "openai", "google", "azure")))
    reg = providers.public_registry()
    check("registry exposes the auth mode", reg["ollama"]["auth"] == "none")
    check("endpoint is a setup field",
          any(f["key"] == "ollama_endpoint"
              for f in reg["ollama"]["extra_fields"]))


def test_ollama_call():
    captured = {}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"] = url
        captured["body"] = json.loads(data)
        captured["timeout"] = timeout
        return FakeResp({"message": {"role": "assistant",
                                     "content": "local says hi"}})

    real_post = providers.requests.post
    providers.requests.post = fake_post
    try:
        out = providers.call("ollama", "", "llama3.1", "SYSTEM",
                             [{"role": "user", "content": "[USER_1] logged in"}],
                             {})
    finally:
        providers.requests.post = real_post
    check("keyless call succeeds", out == "local says hi")
    check("defaults to the local endpoint",
          captured["url"] == providers.OLLAMA_DEFAULT_ENDPOINT + "/api/chat")
    check("system prompt prepended as a system message",
          captured["body"]["messages"][0] == {"role": "system",
                                              "content": "SYSTEM"})
    check("masked text passed through untouched",
          captured["body"]["messages"][1]["content"] == "[USER_1] logged in")
    check("streaming disabled", captured["body"]["stream"] is False)
    check("local calls get the long timeout",
          captured["timeout"] == providers.LOCAL_TIMEOUT)


def test_ollama_custom_endpoint():
    captured = {}

    def fake_post(url, headers=None, data=None, timeout=None):
        captured["url"] = url
        return FakeResp({"message": {"content": "ok"}})

    real_post = providers.requests.post
    providers.requests.post = fake_post
    try:
        providers.call("ollama", "", "llama3.1", "", "hi",
                       {"ollama_endpoint": "http://10.0.0.5:11434/"})
    finally:
        providers.requests.post = real_post
    check("custom endpoint honoured (trailing slash stripped)",
          captured["url"] == "http://10.0.0.5:11434/api/chat")


def test_error_paths():
    try:
        providers.call("ollama", "", "", "s", "hi", {})
        check("missing local model raises a clear error", False)
    except providers.ProviderError as e:
        check("missing local model raises a clear error", "pull" in str(e))
    try:
        providers.call("anthropic", "", "claude-opus-4-8", "s", "hi", {})
        check("cloud provider without key is still refused", False)
    except providers.ProviderError:
        check("cloud provider without key is still refused", True)


def test_list_models():
    def fake_get(url, headers=None, timeout=None):
        assert url.endswith("/api/tags")
        return FakeResp({"models": [{"name": "qwen3:0.6b"},
                                    {"name": "llama3.1:8b"}]})

    real_get = providers.requests.get
    providers.requests.get = fake_get
    try:
        models = providers.list_models("ollama", "", {})
    finally:
        providers.requests.get = real_get
    check("local models listed without a key",
          models == ["llama3.1:8b", "qwen3:0.6b"])


if __name__ == "__main__":
    test_registry()
    test_ollama_call()
    test_ollama_custom_endpoint()
    test_error_paths()
    test_list_models()
    print("\nAll provider tests passed.")
