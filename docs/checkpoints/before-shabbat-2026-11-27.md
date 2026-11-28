# Checkpoint — 2026-11-28 16:45 [before-shabbat-2026-11-27]

## Session summary

The project is mcp-jack: Go, Rust and TypeScript SDKs that wrap MCP with Ed25519 signatures, plus the `jack` CLI. The release line is 0.1.0 (forced by the owner); nothing is published, no tag exists, and the earlier release candidate (run 45894494947 on 12fd955) is superseded once the Rust API changes below land. Work runs as /wrush workers (`rush run --role smart --session <slug> --json`, one worktree per task under `worktrees/`); the parent reviews diffs, commits, opens PRs and merges only on green CI after `gh pr view` shows MERGED, then removes the worktree and branches. Owner rules: no local builds or tests (only cargo fmt/check/clippy, Go build/vet, gofmt, the layout lint), CI waits only through `gh pr checks <n> --watch -i 300` in the background, answers in Russian, nothing is published or tagged without the owner's explicit word.

This stretch was driven by two reviews from future server consumers (Rust `JackLayer`, Windows, Tor). Merged into main: PR 190 and 191 (earlier checkpoints), 192 (`docs/design/onion-and-proxy.md`: Tor and SOCKS5h analysis), 193 (Rust server embedder notes in `docs/operations.md` plus the `FileState` doc comment), 194 (`docs/design/windows-client.md`), 195 (crate-owned `user_key::ServerSigningKey` replaces `ed25519_dalek::SigningKey` in all public places; CI 47/47 on the first run, including the Linux-gated code), 196 (status note in `docs/design/restart-replay.md`, paragraph on synchronous work inside `JackService`). main = 231274b.

Open: PR 197 (`docs/design/rust-api-freeze.md`, branch `rust-api-freeze-doc-1127`, commit d74a0cb) has CI 47/47 green but is NOT merged, because the owner's Shabbat order forbids merging. The document proposes the Rust API shape before the first release: private-field builders for 11 config structs, per-item `#[non_exhaustive]`, a synchronous nonce-admission trait replacing the concrete `Arc<NonceStore>` field type, a typed `Verifier::new` error, approximate call-site counts, owner questions. Two rush worker sessions for it (`rust-api-freeze-doc-1127`, `rust-api-target-1127`) crashed with `batch_fault: jobbatch: commit failed: timeout`, probably from database contention with many unrelated rush workers on this machine; their locks have no holder and their batch roots are stale ("stale incarnation", not stoppable). The second worker's draft was reviewed and accepted by the parent.

The Shabbat stop was ordered for Friday 12:59 and executed on Saturday 16:38 when the session woke (the cron fired late). No worker or watch is running. The owner has not yet answered: Windows client as a product, Tor (document routes only or build SOCKS5h), the API-shape questions in `docs/design/rust-api-freeze.md`, dependency bumps (#284), Go and TypeScript together with Rust, the Go tag.

## Active goal

none: `/goal` is not set.

## TaskList

### in_progress
- none

### pending
- #295 Дизайн-документ: целевой Rust API перед заморозкой 0.1.0 (PR 197 открыт, CI зелёный, не влит; после Шаббата влить и показать владельцу вопросы)
- #286 Rust: nonce-хранилище трейтом и типизированная ошибка Verifier::new (до 0.1.0; ждёт решения владельца по документу)
- #283 Rust: строители и #[non_exhaustive] для 11 Config-структур  (blockedBy: #286)
- #282 Пример и тест: JackLayer + rmcp StreamableHttpService в одном процессе  (blockedBy: #283)
- #281 Документы: остаток (оформление под новый API)
- #284 Rust: выровнять крипто-зависимости и ослабить точные пины (только с разрешения владельца)
- #287 RC 0.1.0 заново на финальном SHA после пакета Rust-API  (blockedBy: #281, #282, #283)
- #271 Владелец: опубликовать заглушку mcp-jack@0.0.0
- #272 Владелец: окружение release и Trusted Publishing  (blockedBy: #271, #287)
- #101 Публикация 0.1.0  (blockedBy: #272)
- #273 Go-модуль: тег v0.1.0, решение владельца
- #274 Проверить только чтением настройки репозитория
- #288 После 0.1.0: клиент на Windows (дизайн готов: PR 194)  (blockedBy: #101)
- #289 После 0.1.0: Tor, SOCKS5h и http для .onion (разбор готов: PR 192)  (blockedBy: #101)
- #290 После 0.1.0: Rust, ротация ключа сервера вне Linux  (blockedBy: #101)
- #128 Бэклог после 0.1.0: Dependabot, паритет Rust/TS по хранилищу доверия, прочее  (blockedBy: #101)

### recently completed
- #296 Гигиена документов (PR 196)
- #294 Устаревшие утверждения о durable nonce (PR 196)
- #293 Дизайн-документ: Tor и SOCKS5h (PR 192)
- #292 Дизайн-документ: клиент на Windows (PR 194)
- #291 Документы для серверных потребителей (PR 193)
- #280 Rust: свой тип ключа сервера (PR 195)
- #278 Чекпоинт now-2026-11-26-223235 в main (PR 191)
- #277 Go client/rotation: сетевой шов NewHTTPWithTransport (PR 189)
- #270 RC 0.1.0 на 12fd955
- #268 Go client/rotation: интерфейс ClientTrustState

## Decisions

- Publication was set aside by the owner ("пока забудь про публикацию"); focus moved to the future consumers' requests. The hub/proxy-server idea was explicitly postponed.
- The Rust API is reshaped before the first release as a deliberate break (the crate is unpublished); the work is split into #286, then #283, run one after the other because they edit the same files.
- A rush worker fault is not retried into the same session; a fresh session or the parent's own acceptance is used. Linux-gated Rust code is left to CI, since local checks run only on Windows.
- Documentation tasks are accepted after at most two review rounds; small corrections the parent makes itself.
- Nothing is merged, pushed to main, published or tagged during Shabbat.

## Open questions

1. Windows client as a product (design in `docs/design/windows-client.md`): yes or no.
2. Tor: only document today's routes, or build built-in SOCKS5h; any new dependency needs approval.
3. API-shape questions of `docs/design/rust-api-freeze.md` (builders versus `#[non_exhaustive]`, nonce trait scope, sync or async, mirror in Go and TypeScript, which enums).
4. May dependencies be bumped (#284)?
5. Do Go and TypeScript release together with Rust?
6. Go tag `v0.1.0`; read-only repository settings check (#274); publication steps (#271, #272, #101) stay with the owner.
7. Where `ServerSigningKey` should live (currently `user_key`).

## Repo state

### main folder [main]

```
(clean, local main equals origin/main at 231274b; this checkpoint is committed locally on top and not pushed)
```

```
231274b Merge pull request #196 from PHPCraftdream/docs-hygiene-1127
ad78b0c Mark the restart-replay design as a baseline; note synchronous work in the Rust service
d12a4a5 Merge pull request #195 from PHPCraftdream/rust-key-1127
b2baec2 Own the server signing key type instead of exposing ed25519-dalek
cd50281 Merge pull request #194 from PHPCraftdream/windows-client-1127
```

Open PRs: 197 (design, green, not merged) and nine Dependabot PRs (28, 32, 102, 176 to 181) deliberately left until after the release.

### worktrees

- rust-api-freeze-doc-1127 [rust-api-freeze-doc-1127] — holds PR 197 (the Rust API shape design); clean; last d74a0cb Add the design for the Rust API shape before the first release. Remove it after PR 197 is merged.
- No other worktrees and no running workers or watches. This session runs in the main folder.
