# SSH-certifikater

Key-Box giver ikke agenter en SSH-nøgle til en kundeserver. Agenten laver
selv et nøglepar, og Key-Box underskriver et **certifikat** til det. Det gælder
kort tid, ét brugernavn, kun fra agentmaskinens adresse, og kan være låst til
én kommando.

## Én gang pr. kunde: en certifikat-autoritet (CA)

Hver kunde får sin egen CA. Et certifikat til kunde A virker derfor aldrig hos
kunde B.

1. Lav nøgleparret på din egen maskine, uden adgangskode:

   ```sh
   ssh-keygen -t ed25519 -N "" -C "keybox-ca-KUNDE" -f keybox-ca-KUNDE
   ```

2. Læg hele indholdet af `keybox-ca-KUNDE` (den private del) i Vaultwarden som
   en **Secure note** med navnet `ssh-ca-KUNDE`, i den samling Key-Box' bruger
   kan læse. Slet filen bagefter.
3. Behold `keybox-ca-KUNDE.pub`. Den er ikke hemmelig og skal ud på kundens
   servere.

Kun Ed25519 uden adgangskode accepteres.

## Én gang pr. server: den færdige pakke

`deploy/server/` indeholder et script, der sætter en server op, og de faste
kommandoer, en agent kan køre. Kopiér mappen og CA'ens offentlige nøgle til
serveren, og kør som root:

```sh
./keybox-server-setup.sh fuld   keybox-ca-KUNDE.pub docker:web nginx.service
./keybox-server-setup.sh status keybox-ca-KUNDE.pub
```

| Tilstand | Agenten kan |
|---|---|
| `status` | Kun køre den skrivebeskyttede oversigt. Serveren håndhæver det selv, uanset certifikat. Til maskiner, agenter ikke må kunne ændre. |
| `fuld` | Oversigt, fejllog, sikkerhedsopdateringer, genstart af de navngivne tjenester, og en fuld shell som en særskilt bruger. |

De tilhørende handlinger i policyen, med `principal` og `force_command`:

| Handling | Niveau | principal | force_command |
|---|---|---|---|
| `status` | 1 | `keybox-agent` | `/usr/local/lib/keybox/status` |
| `logs` | 2 | `keybox-agent` | `sudo /usr/local/lib/keybox/logs` |
| `opdater` | 2 | `keybox-agent` | `sudo /usr/local/lib/keybox/opdater` |
| `genstart-NAVN` | 2 | `keybox-agent` | `sudo /usr/local/lib/keybox/genstart NAVN` |
| `genstart-server` | 2 | `keybox-agent` | `sudo /usr/local/lib/keybox/genstart-server` |
| `shell` | 3 | `keybox-admin` | (ingen) |

`genstart` genstarter kun navne, der står i `/etc/keybox-agent/tjenester` på
serveren, uanset hvad policyen eller certifikatet siger.

`genstart-server` genstarter hele serveren ét minut efter, at kommandoen er
kørt. Tjek først, at serverens tjenester starter af sig selv ved opstart.

## Én gang pr. server: i hånden

Som root på kundens server. Serveren skal kun stole på CA'en for den ene
bruger, agenten må logge ind som, ikke for alle brugere. Så kan CA'en aldrig
bruges til at blive root, selv hvis Key-Box' policy skulle være forkert.

```sh
install -m 0644 keybox-ca-KUNDE.pub /etc/ssh/keybox_ca.pub
cat > /etc/ssh/sshd_config.d/50-keybox.conf <<'EOF'
Match User deploy
    TrustedUserCAKeys /etc/ssh/keybox_ca.pub
    AuthorizedKeysFile none
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
EOF
sshd -t && systemctl reload ssh
```

Tjek bagefter, at reglen kun gælder den bruger:

```sh
sshd -T -C user=root,host=x,addr=1.2.3.4   | grep -i trustedusercakeys   # none
sshd -T -C user=deploy,host=x,addr=1.2.3.4 | grep -i trustedusercakeys   # /etc/ssh/keybox_ca.pub
```

Brugeren skal findes på serveren og have en rigtig shell (`/bin/sh`), også når
den kun må køre én kommando; `sshd` starter kommandoen gennem shellen.

Skal en handling være låst til en kommando, så læg kommandoen på serveren som
et script, der ejes af root, fx `/usr/local/bin/deploy`.

## I kundens policy-fil

```toml
[customers.KUNDE.systems.web01.actions.deploy]
level   = 2
agents  = ["hermes"]
targets = ["web01.kunde.dk"]
pin     = "commit"

[customers.KUNDE.systems.web01.actions.deploy.method.ssh_cert]
ca             = "ssh-ca-KUNDE"
principal      = "deploy"
source_address = ["100.64.0.10"]          # agentmaskinens adresse
force_command  = "/usr/local/bin/deploy {commit}"
ttl_secs       = 600
```

- `pin = "commit"` betyder, at du godkender én bestemt commit, og at
  certifikatet kun kan køre scriptet med netop den.
- Uden `force_command` får agenten en almindelig shell som den bruger. Brug
  det sparsomt.

## Hvad agenten gør

```sh
ssh-keygen -t ed25519 -N "" -C "" -f /run/hermes/k        # nyt nøglepar pr. opgave
keyboxd call … '{"op":"fetch","id":"…","public_key":"ssh-ed25519 AAAA…"}'
# svaret indeholder "certificate"; gem det som /run/hermes/k-cert.pub
ssh -i /run/hermes/k deploy@web01.kunde.dk
```

Sender agenten ikke `public_key`, svarer Key-Box `ssh-public-key-required`,
og godkendelsen er ikke brugt.

## Det, et certifikat ikke kan

- Videresende porte, SSH-agent eller X11. Det er altid slået fra.
- Bruges fra en anden adresse end `source_address`.
- Bruges efter udløb. Højst 30 minutter; vælg kortere.

## Det, Key-Box ikke kan

- **Trække et certifikat tilbage.** Det virker, til det udløber, også efter et
  nødstop. Derfor er levetiden kort.
- **Afbryde en session, der allerede er åben.** `sshd` tjekker kun udløbet ved
  login. En agent, der er logget ind, bliver siddende, til forbindelsen lukkes.
  En låst kommando, der afslutter af sig selv, har ikke det problem.
