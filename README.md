# afternoon

Afternoon — a personal agent, built in one.

A static, single-page personal agent. Bring your own model key; memory, tasks
and chat history live in your browser only. Hosted on GitHub Pages.

## Providers

- **Token Harbor** (default) — `https://tokenharbor.ai/v1/chat/completions`.
  Free models first (`deepseek-v4.1-flash:free`, `mimo-v2.5:free`), then
  `muse-spark-1-3`, `kimi-k3`, `glm-5.3-flash`, `gemini-3.8-flash`.
- **OpenRouter** — `https://openrouter.ai/api/v1/chat/completions`.
- **NVIDIA NIM** — self-hosted NIM at an editable localhost/LAN `/v1` endpoint. Hosted `nvapi-` keys are browser-locked: the documented host is CORS-restricted and NVCF does not expose the hosted catalog/chat path. A one-token completion validates the local endpoint and key before it is stored.

Keys are stored per provider, on this device only, and sent only to that
provider's endpoint. Keys are never logged, embedded in the page, or exported
in plaintext.

## Security

- Strict CSP via meta tag: `default-src 'none'`; `connect-src` limited to the
  provider origins and localhost for self-hosted NIM; `form-action 'none'`; `base-uri 'none'`; no inline scripts or
  styles. (`frame-ancestors` is header-only and ignored in a meta tag — noted
  honestly; GitHub Pages sets its own headers.)
- `Referrer-Policy: no-referrer` via meta.
- Input length caps and validation throughout; rendered content is escaped.

## Encryption at rest by default (E2EE)

New users create a passphrase during onboarding, before any provider key or other
data is stored. AES-GCM-256 protects memory, tasks, chat history and API keys;
the key is derived with PBKDF2-SHA256 at 310,000 iterations. The passphrase is
never stored; a lock screen greets every reload; exports stay encrypted and can
only be re-imported with the passphrase. Existing plaintext installs are detected
and offered an in-place migration. Plaintext is removed only after the encrypted
vault has been written successfully.

## Pre-push secret scan

Run `./scan.sh` before every push. It refuses the push when anything shaped
like a real credential (Token Harbor keys, `sk-` API keys, GitHub PATs, bearer
tokens, hardcoded password assignments) appears in tracked files.

