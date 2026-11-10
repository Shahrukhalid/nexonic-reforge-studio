"""Milestone 7 tests: AI Assistant, credentials, context building, client."""
import threading

from reforge.ai import credentials, stream_chat
from reforge.ai.context import SYSTEM_PROMPT, build_project_context
from reforge.analysis.orchestrator import Orchestrator
from reforge.ui.main_window import MainWindow


def test_credentials_lifecycle():
    prov = "test_provider_x"
    test_key = "sk-test-secret-key-12345"
    credentials.set_key(prov, test_key)
    got = credentials.get_key(prov)
    assert got == test_key
    credentials.delete_key(prov)
    assert credentials.get_key(prov) is None


def test_context_builder(db, samples):
    pid = db.create_project("test_ai", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    ctx_text = build_project_context(db, pid)
    assert "PROJECT ANALYSIS CONTEXT" in ctx_text
    assert "Flutter" in ctx_text
    assert SYSTEM_PROMPT != ""


def test_ai_client_stream_cancellation(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def __iter__(self):
            yield b'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n'
            yield b'data: {"choices": [{"delta": {"content": " world"}}]}\n\n'
            yield b'data: [DONE]\n\n'

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: FakeResponse())

    stop = threading.Event()
    tokens = list(stream_chat("openai", "fake-key", "gpt-4o", [{"role": "user", "content": "hi"}], stop_event=stop))
    assert "".join(tokens) == "Hello world"

    # Test cancellation early
    stop.set()
    tokens_stopped = list(stream_chat("openai", "fake-key", "gpt-4o", [{"role": "user", "content": "hi"}], stop_event=stop))
    assert tokens_stopped == []


def test_ai_assistant_page(db, samples, qapp):
    win = MainWindow()
    win.ctx.db = db
    pid = db.create_project("test_ai_gui", str(samples["apk"]), "standard")
    Orchestrator(db).analyze(pid)

    page = win.pages["AI Assistant"]
    page.refresh(select=pid)

    assert page.current_pid == pid
    assert page.ctx_preview.toPlainText() != ""

    # Test provider dropdown switch
    page.prov_sel.setCurrentIndex(1)  # OpenAI
    assert page.model_input.text() != ""

    page.prov_sel.setCurrentIndex(4)  # Local
    assert "localhost" in page.url_input.text()

    # Preset chip insertion
    page._insert_preset("Summarize architecture")
    assert page.prompt_edit.toPlainText() == "Summarize architecture"

    win.close()
