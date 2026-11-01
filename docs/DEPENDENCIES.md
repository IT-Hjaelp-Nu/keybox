# Afhængigheder – forslag til godkendelse

**Status 11. oktober 2026:** listen nedenfor blev godkendt af Christian og er
taget i brug. Alt uden for den kræver stadig godkendelse.

Tilføjet siden, med godkendelse: `rcgen` (agenternes klientcertifikater).
Installeret program, ikke en crate: `rbw` (henter fra Vaultwarden).

Det, der faktisk bygges ind i `keyboxd` på Linux, er 93 fremmede crates
(`cargo tree -e normal,build --target x86_64-unknown-linux-gnu`). Tallene i
tabellen er fra forslaget og er målt for hver crate alene.

**Undtagelse i `cargo audit`:** RUSTSEC-2023-0071 (`rsa`). Craten står i
`Cargo.lock` som valgfri del af `ssh-key`, men bygges ikke ind. Begrundelsen
står i `.cargo/audit.toml`, og `deny.toml` forbyder craten.

## Listen

| Crate | Bruges til | Vedligeholdes af | Trækker med (alene) |
|---|---|---|---|
| `tokio` 1.53 | Async runtime, Unix-socket, timeouts. Giver `peer_cred()` (SO_PEERCRED) uden `unsafe` hos os. | tokio-rs | 13 |
| `hyper` + `hyper-util` + `http-body-util` | HTTP/1 til godkendelsessiden og klient til GitHub. Størrelsesloft på bodies. | hyperium (Sean McArthur) | deles med tokio; hele HTTP-laget +16 |
| `rustls` 0.23 + `tokio-rustls` 0.26 | TLS, server og klient. Med `ring`, ikke standardvalget `aws-lc-rs` (som kræver cmake). | rustls-holdet (ctz, djc, cpu) | 17 |
| `webpki-roots` | Mozillas rodcertifikater til kaldet mod api.github.com. | rustls-holdet | 1 |
| `ring` 0.17 | SHA-256 (hash-kæde), tilfældige tal, RS256 (GitHub App-JWT), ECDSA P-256 (passkey-signaturer). Er allerede med via rustls. | Brian Smith | 8 (C/asm via `cc`) |
| `rusqlite` 0.40 (`bundled`) | Tilstand og log. SQLite kompileres med ind. | rusqlite (gwenn) | 14 (C via `cc`) |
| `serde` + `serde_json` | Agent-API'ets beskeder og WebAuthn-JSON. `deny_unknown_fields` overalt. | David Tolnay | 7 + 5 |
| `toml` 1.1 | Policy-filen. | toml-rs (Ed Page) | 7 |
| `zeroize` + `secrecy` | Hemmeligheder, der nulstilles og ikke kan `Debug`-printes. | RustCrypto / iqlusion (Tony Arcieri) | 6 + 2 |
| `ssh-key` 0.6 (`ed25519`) | Udstede SSH-certifikater. | RustCrypto | 32 (ren Rust: ed25519-dalek, sha2 m.fl.) |
| `proptest` 1.12 (kun test) | Fuzz-lignende test af parseren på stabil Rust, kører i `cargo test`. | proptest-rs | 26 |

## Fravalgt, med begrundelse

| Crate | Hvorfor ikke |
|---|---|
| `webauthn-rs` 0.5 | **Linker OpenSSL** (`openssl`, `openssl-sys`) og trækker 101 crates. Se afsnittet nedenfor – det er en beslutning for Christian. |
| `webauthn_rp` | 103 crates og bruger `rsa`, som har en åben advarsel (RUSTSEC-2023-0071). `cargo audit` ville ikke være grøn. |
| `passkey` (1Password) | 118 crates; mest rettet mod klient/authenticator-siden. |
| `axum` | 43 crates alene; hele sættet bliver 111 i stedet for 95. Siden har 6–8 ruter, så `hyper` direkte er nok. |
| `reqwest` | Til ét kald mod GitHub er `hyper` + `rustls` nok. |
| `jsonwebtoken`, `rsa` | GitHub App-JWT er tre base64-felter og én RS256-signatur; `ring` kan det. |
| `chrono`/`time`, `uuid`, `clap`, `tracing`, skabelonmotorer | Unix-sekunder, tilfældige hex-id'er, tre underkommandoer og håndskrevet HTML med én escape-funktion dækker behovet. |
| `cargo-fuzz` | Kræver nightly. Kan tilføjes senere i en mappe uden for workspacet, hvis ønsket. |

## Beslutning: WebAuthn

Kravet er rustls og ikke OpenSSL. `webauthn-rs` er det modne, reviderede valg,
men det bruger OpenSSL til al sin krypto.

| | A: `webauthn-rs` | B: egen, snæver verifikation oven på `ring` |
|---|---|---|
| Nye crates | ca. 75 oveni (målt: 185 mod 111), samt systemets OpenSSL | 0 |
| Kode vi selv skal stå inde for | Lidt | Ca. 250 linjer i den mest kritiske sti |
| Dækker | Hele standarden | Kun det, vi bruger: ES256, attestation "none", UV krævet, ingen udvidelser |

**Besluttet 11. oktober 2026: B.** Det, Key-Box skal kontrollere, er lille og præcist
specificeret: `clientDataJSON` (type, challenge, origin), `authenticatorData`
(RP ID-hash, flagene UP og UV, tæller) og én ECDSA P-256-signatur. Samsung Pass
og YubiKey bruger ES256. Ved registrering uden attestation er den offentlige
nøgle alligevel ikke bevist af andre end browseren, så den kan tages fra
`getPublicKey()` uden CBOR-parser. Koden testes mod kendte vektorer og med
negative tests for hvert felt.

Vælges A, skal kravet "ikke OpenSSL" lempes for denne ene afhængighed.

## Værktøjer

`cargo-audit` og `cargo-deny` er ikke installeret på udviklingsmaskinen, og der
er ingen `rustup` (Rust 1.99.0 kommer fra Arch-pakken, så `rust-toolchain.toml`
håndhæves ikke lokalt). Begge dele skal på plads, før "grøn" kan vises.

Ingen GitHub Actions er tilføjet. Forslag, når det ønskes: én workflow med
`actions/checkout` pinnet til commit-SHA, og resten som rene `cargo`-kommandoer.
