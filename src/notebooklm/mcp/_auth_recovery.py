"""Opt-in, signed browser hand-off for replacing a NotebookLM Web session.

Phase 1: recover via an already-valid storage_state.json chosen in the browser.
This is NOT Google OAuth: it does not imply that signing in to Google in a
separate tab will grant the server any Google cookies. A server-hosted browser
login can be integrated later without changing the MCP action contract.

Only enabled when NOTEBOOKLM_MCP_REAUTH_LINKS=1 and an HTTPS public URL exists.
The signing key is ephemeral and the link is short-lived and one-use.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastmcp import Context
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response

from ..client import NotebookLMClient
from ..paths import get_storage_path
from ._context import reload_client_from_app
from ._context import get_profile_state
from ._filelink import FileLinkError, FileTransferConfig

if TYPE_CHECKING:
    from fastmcp import FastMCP

MAX_AUTH_BYTES = 1024 * 1024
LINK_TTL_SECONDS = 5 * 60
ENV_ENABLE = "NOTEBOOKLM_MCP_REAUTH_LINKS"
ENV_EXPECTED_ACCOUNT = "NOTEBOOKLM_MCP_EXPECTED_GOOGLE_ACCOUNT"

HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; form-action 'none'; base-uri 'none'"
    ),
}

UPLOAD_PAGE = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recuperar acesso ao NotebookLM</title></head>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1.2rem">
<h1>Recuperar acesso ao NotebookLM</h1>
<p>Selecione o arquivo <code>storage_state.json</code> gerado pelo login do
NotebookLM no seu computador. Ele contém credenciais privadas da sua conta
Google; envie apenas para o seu próprio servidor Railway.</p>
<p>Este fluxo ainda não abre o login do Google no navegador remoto.</p>
<input type="file" id="file" accept=".json,application/json">
<button id="send" type="button">Atualizar sessão</button>
<p id="result" role="status"></p>
<script>
document.getElementById('send').onclick = async () => {
  const f = document.getElementById('file').files[0];
  const msg = document.getElementById('result');
  if (!f) { msg.textContent = 'Escolha o arquivo antes de continuar.'; return; }
  msg.textContent = 'Validando arquivo...';
  try {
    const r = await fetch(location.href, {method:'POST',
      headers:{'Content-Type':'application/json'}, body:f});
    msg.textContent = await r.text();
  } catch (_) { msg.textContent = 'Falha na comunicação com o servidor.'; }
};
</script></body></html>"""


def _validate_storage(raw: bytes, expected_account: str) -> dict[str, Any]:
    """Reject malformed, incomplete or account-mismatched credential snapshots.

    The metadata is *not* cryptographic proof of account ownership. An authorized
    link-holder is trusted to upload their own snapshot; an end-to-end token fetch
    must still be checked before claiming authentication was restored.
    """
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("JSON inválido.") from exc
    if not isinstance(data, dict):
        raise ValueError("O arquivo precisa ser um objeto JSON.")
    cookies = data.get("cookies")
    if not isinstance(cookies, list) or len(cookies) > 300:
        raise ValueError("Lista de cookies inválida.")
    names = {x.get("name") for x in cookies if isinstance(x, dict)}
    if "SID" not in names or "__Secure-1PSIDTS" not in names:
        raise ValueError("Arquivo incompleto: cookies de autenticação ausentes.")
    meta = data.get("notebooklm")
    account = meta.get("account") if isinstance(meta, dict) else None
    email = account.get("email") if isinstance(account, dict) else None
    if not isinstance(email, str) or email.casefold() != expected_account.casefold():
        raise ValueError("O arquivo não corresponde à conta Google configurada.")
    return data


async def _check_live_storage(raw: bytes, expected_account: str) -> bytes:
    """Check a candidate against Google before replacing the working session."""
    with tempfile.TemporaryDirectory(prefix="notebooklm-auth-check-") as directory:
        candidate = Path(directory) / "storage_state.json"
        candidate.write_bytes(raw)
        candidate.chmod(0o600)

        async def _run() -> None:
            async with NotebookLMClient.from_storage(path=candidate) as client:
                await client.settings.get_user_settings()
                actual_email = await client.get_account_email(live_fallback=True)
                if not actual_email or actual_email.casefold() != expected_account.casefold():
                    raise ValueError("Conta Google diferente da esperada.")

        await asyncio.wait_for(_run(), timeout=60)
        return candidate.read_bytes()


def _write_storage(storage: Path, raw: bytes) -> None:
    """Write to the target filesystem atomically, without logging credential data."""
    storage.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(prefix=".notebooklm-reauth-", dir=storage.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmpname, storage)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)


def register_auth_recovery(mcp: FastMCP, config: FileTransferConfig | None) -> None:
    """Add a minimal opt-in recovery tool + signed handoff routes.

    Never enable a cookie-replacement endpoint by default. Single-process
    deployments are assumed: link signer / replay state live in memory.
    """
    if os.environ.get(ENV_ENABLE) != "1" or config is None:
        return
    expected = (os.environ.get(ENV_EXPECTED_ACCOUNT) or "").strip()
    if not expected or "@" not in expected:
        raise ValueError(f"{ENV_EXPECTED_ACCOUNT} must be set for reauth links")

    @mcp.tool
    async def auth_recovery_link(ctx: Context) -> dict[str, Any]:
        """Get a secure 5-minute reauthentication hand-off link after an AUTH error.

        This initial browser flow can accept a previously generated
        storage_state.json; Google browser login itself is not yet supported.
        The link contains a single-use capability; share it only with the owner.
        """
        state = get_profile_state(ctx)
        if state.profile is None:
            raise ValueError("A single Web profile is required.")
        token = config.signer.sign(
            {"op": "auth-recover", "profile": state.profile}, LINK_TTL_SECONDS
        )
        return {
            "status": "authentication_required",
            "recovery_url": f"{config.base_url.rstrip('/')}/auth/recover/{token}",
            "expires_in_seconds": LINK_TTL_SECONDS,
            "method": "existing_storage_file",
        }

    @mcp.custom_route("/auth/recover/{token}", methods=["GET", "POST"])
    async def recovery_route(request: Request) -> Response:
        try:
            payload = config.signer.verify(
                request.path_params["token"], op="auth-recover"
            )
        except FileLinkError:
            return PlainTextResponse(
                "Link inválido ou expirado.", status_code=403, headers=HEADERS
            )
        if request.method == "GET":
            return HTMLResponse(UPLOAD_PAGE, headers=HEADERS)

        if request.headers.get("origin") not in (None, config.base_url.rstrip("/")):
            return PlainTextResponse("Origem inválida.", status_code=403, headers=HEADERS)
        jti = payload.get("jti")
        if not isinstance(jti, str) or not config.jti_store.try_begin(jti):
            return PlainTextResponse("Link já utilizado.", status_code=403, headers=HEADERS)
        committed = False
        try:
            raw = bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > MAX_AUTH_BYTES:
                    return PlainTextResponse("Arquivo muito grande.", status_code=413, headers=HEADERS)
            try:
                _validate_storage(bytes(raw), expected)
            except ValueError as exc:
                return PlainTextResponse(str(exc), status_code=400, headers=HEADERS)
            profile = payload.get("profile")
            if not isinstance(profile, str) or not profile:
                return PlainTextResponse("Perfil inválido.", status_code=403, headers=HEADERS)
            try:
                checked_raw = await _check_live_storage(bytes(raw), expected)
            except (Exception, asyncio.TimeoutError):
                # Never replace the active profile when Google rejects the candidate.
                return PlainTextResponse(
                    "O Google não aceitou essa sessão. Faça login novamente e tente outro arquivo.",
                    status_code=422, headers=HEADERS,
                )
            try:
                _write_storage(get_storage_path(profile=profile), checked_raw)
            except OSError:
                return PlainTextResponse("Não foi possível salvar a sessão.", status_code=500, headers=HEADERS)
            # Burn the link as soon as credentials are written, even when a
            # subsequent in-memory client reload fails.
            config.jti_store.commit(jti, int(payload["exp"]))
            committed = True
            # Drop cached, expired client credentials. The next MCP call opens
            # the newly persisted snapshot without restarting Railway.
            try:
                await reload_client_from_app(request, profile=profile)
            except Exception:
                # Credentials are persisted; a later service restart can reload.
                return PlainTextResponse(
                    "Sessão atualizada e validada; reinicie o MCP para carregar a nova sessão.",
                    status_code=202, headers=HEADERS,
                )
            return PlainTextResponse(
                "Acesso restaurado. Volte ao ChatGPT e repita sua consulta.",
                headers=HEADERS,
            )
        finally:
            if not committed:
                config.jti_store.rollback(jti)
