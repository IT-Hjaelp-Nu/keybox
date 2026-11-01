# Installation på vault-serveren

Sådan får du Key-Box op at køre og prøver godkendelsessiden fra telefonen.
Alt køres på vault-serveren som root, medmindre andet står.

**Status:** Key-Box kan modtage anmodninger og godkende dem med passkey. Den
udleverer endnu ingen adgange (GitHub og SSH mangler). Vejledningen er ikke
afprøvet på en rigtig server; sig til, hvor den ikke passer.

## Du skal bruge

- Rust (samme version som i `rust-toolchain.toml`) til at bygge.
- Tailscale på serveren og på telefonen, med **HTTPS-certifikater slået til**
  i Tailscales adminpanel (DNS → HTTPS Certificates).
- Serverens Tailscale-navn og -adresse:

  ```sh
  tailscale status --self --json | grep DNSName   # fx vault.eksempel.ts.net
  tailscale ip -4                                  # fx 100.x.y.z
  ```

I resten af vejledningen står `NAVN` for navnet og `ADRESSE` for adressen.

## 1. Byg og læg programmet på plads

```sh
cargo build --release -p keyboxd
install -m 0755 target/release/keyboxd /usr/local/bin/keyboxd
```

## 2. Bruger og mapper

```sh
useradd --system --home-dir /var/lib/keybox --shell /usr/sbin/nologin keybox
install -d -m 0750 -o root -g keybox /etc/keybox
install -d -m 0700 -o keybox -g keybox /var/lib/keybox
install -d -m 0750 -o root -g keybox /etc/keybox/policy.d
install -m 0640 -o root -g keybox policy.example.toml /etc/keybox/policy.d/eksempel.toml
install -m 0640 -o root -g keybox deploy/keyboxd.env.example /etc/keybox/keyboxd.env
```

Ret `/etc/keybox/keyboxd.env`: sæt `ADRESSE` og `NAVN` ind.

Policyen ligger som filer i `/etc/keybox/policy.d/`: én fil pr. kunde (fx
`bager-jensen.toml`) og én med GitHub App'en (`apps.toml`). Eksemplet er
opdigtet; erstat det med dine egne. Tjek filerne, før du går videre:

```sh
keyboxd check-policy /etc/keybox/policy.d
```

Filerne er kun et forslag. Key-Box bruger dem først, når du har godkendt dem
med passkey på godkendelsessiden, og sådan er det også ved hver senere ændring.

## 3. Certifikat til godkendelsessiden

```sh
tailscale cert --cert-file /etc/keybox/web.crt --key-file /etc/keybox/web.key NAVN
chown root:keybox /etc/keybox/web.crt /etc/keybox/web.key
chmod 0640 /etc/keybox/web.crt /etc/keybox/web.key
```

Certifikatet gælder 90 dage. Fornyelse er ikke automatiseret endnu: kør de
tre linjer igen og genstart Key-Box.

## 4. Key-Box' eget certifikat-system til agenterne

```sh
sudo -u keybox keyboxd init-pki --dir /var/lib/keybox --name NAVN
```

## 5. Start

```sh
install -m 0644 deploy/keyboxd.service /etc/systemd/system/keyboxd.service
systemctl daemon-reload
systemctl enable --now keyboxd
systemctl status keyboxd
```

## 6. Registrér dine to passkeys

1. Lav et engangs-token (gælder 10 minutter, én brug):

   ```sh
   sudo -u keybox keyboxd enroll-token --dir /var/lib/keybox
   ```

2. Åbn `https://NAVN:8444/` på telefonen (Tailscale slået til).
3. Skriv et navn (fx `telefon`), indsæt token, tryk **Registrér første passkey**.
4. Gentag med et nyt token og din reserve (fx en YubiKey med navnet
   `yubikey`). Hver ny passkey kræver sit eget token.

Når siden viser "Key-Box kører.", tager den imod anmodninger fra agenter.

## 7. Giv en agent adgang

```sh
sudo -u keybox keyboxd issue-agent --dir /var/lib/keybox --out /var/lib/keybox/ud hermes
```

Flyt `hermes.key`, `hermes.pem` og `/var/lib/keybox/agent-ca.pem` til
agentmaskinen, så kun Hermes' bruger kan læse dem, og slet
`/var/lib/keybox/ud`. Agentens navn skal stå under `agents` i policy-filen.

Prøv fra agentmaskinen:

```sh
keyboxd call --addr ADRESSE:8443 --name NAVN \
  --ca agent-ca.pem --cert hermes.pem --key hermes.key \
  '{"op":"request","customer":"...","system":"...","action":"...","target":"...","reason":"prøve"}'
```

Anmodningen skal nu stå på siden på telefonen.

## Notifikationer på telefonen

Key-Box kan give besked, når noget venter på dig. Den skal have lov til at nå
Googles push-tjeneste:

```sh
install -d /etc/systemd/system/keyboxd.service.d
install -m 0644 deploy/keyboxd.service.d/push.conf /etc/systemd/system/keyboxd.service.d/push.conf
systemctl daemon-reload && systemctl restart keyboxd
```

Åbn derefter siden på telefonen i Chrome eller Samsung Internet, tryk **Slå til
på denne enhed** under Notifikationer, giv browseren lov, og godkend med
passkey. Der kommer straks en notifikation, som viser, at det virker.

## Efterse loggen

```sh
sudo -u keybox keyboxd verify-log /var/lib/keybox/audit.log
```

Tallet og hashen skal passe med det, der står nederst på godkendelsessiden.
Loggen kan låses, så gamle linjer ikke kan ændres, heller ikke af Key-Box selv:

```sh
chattr +a /var/lib/keybox/audit.log
```

## Anbefalet: luk siden for alt andet end telefonen

Agentmaskinen er på samme Tailscale-net og kan ellers åbne godkendelsessiden.
Den kan ikke godkende noget, men den kan afvise anmodninger. Lav en ACL i
Tailscale, så kun telefonen når port 8444, og kun agentmaskinen når port 8443.

## Mistet eller stjålet telefon

Nødstop kræver en passkey, så uden telefonen (og uden reserve) stoppes Key-Box
fra serveren. Gør det i denne rækkefølge:

```sh
ssh vault
systemctl stop keyboxd                                   # nu udleveres intet
sudo -u keybox keyboxd remove-passkey --dir /var/lib/keybox telefon
```

Suspendér derefter GitHub App'en i GitHub (organisationen → Settings → GitHub
Apps → Configure → Suspend), så tokens, der allerede er udleveret, dør. SSH-
certifikater udløber af sig selv inden for højst 30 minutter.

Når du har en ny enhed:

```sh
systemctl start keyboxd
sudo -u keybox keyboxd enroll-token --dir /var/lib/keybox
```

og registrér den på siden. Husk at tilføje den nye enheds Tailscale-adresse til
`KEYBOX_WEB_ALLOW` i `/etc/keybox/keyboxd.env`, og fjerne den gamle.

En passkey kan ikke tilføje en anden passkey. Det kræver altid et token fra
serveren, så den, der har din telefon, ikke kan lave sin egen adgang.

## Hvis noget går galt

```sh
journalctl -u keyboxd -n 50
```

| Besked | Betyder |
|---|---|
| `i/o: address not available` | Tailscale-adressen findes ikke endnu, eller står forkert i `keyboxd.env`. |
| `audit log: chain is broken at line N` | Logfilen er ændret eller halvt skrevet. Key-Box starter ikke, før du har set på den. |
| `key or certificate could not be made or read` | `web.crt`/`web.key` mangler eller kan ikke læses af brugeren `keybox`. |
| `refusing to listen on all interfaces` | Der står `0.0.0.0` i `keyboxd.env`. |
