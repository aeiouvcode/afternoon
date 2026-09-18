# afternoon

Afternoon — a personal agent, built in one.

A static, single-page personal agent. Bring your own model key; memory, tasks
and chat history live in your browser only. Hosted on GitHub Pages.

## Providers

- **Token Harbor** (default) — `https://tokenharbor.ai/v1/chat/completions`.
  Free models first (`deepseek-v4.1-flash:free`, `mimo-v2.5:free`), then
  `muse-spark-1-3`, `kimi-k3`, `glm-5.3-flash`, `gemini-3.8-flash`.
- **OpenRouter** — `https://openrouter.ai/api/v1/chat/completions`.

Keys are stored per provider, on this device only, and sent only to that
provider's endpoint. Keys are never logged, embedded in the page, or exported
in plaintext.

## Security

- Strict CSP via meta tag: `default-src 'none'`; `connect-src` limited to the
  two providers; `form-action 'none'`; `base-uri 'none'`; no inline scripts or
  styles. (`frame-ancestors` is header-only and ignored in a meta tag — noted
  honestly; GitHub Pages sets its own headers.)
- `Referrer-Policy: no-referrer` via meta.
- Input length caps and validation throughout; rendered content is escaped.

## Optional encryption at rest (E2EE)

Opt in from the context panel. AES-GCM-256 for memory, tasks, chat history and
API keys; key derived with PBKDF2-SHA256 at 310,000 iterations. The passphrase
is never stored; a lock screen greets every reload; exports stay encrypted and
can only be re-imported with the passphrase.

## Pre-push secret scan

Run `./scan.sh` before every push. It refuses the push when anything shaped
like a real credential (Token Harbor keys, `sk-` API keys, GitHub PATs, bearer
tokens, hardcoded password assignments) appears in tracked files.
