# Sikkerhed i Key-Box

Key-Box er den eneste vej, hvorpå IT Hjælp Nu's AI-agenter kan få adgang til
kundesystemer. Er Key-Box forkert, kan en narret agent nå alle kunder. Dette
dokument beskriver, hvem vi bygger imod, hvordan hvert krav håndhæves, og hvad
der ikke er løst.

Christian er eneste bruger og eneste, der kan godkende.

## Trusselsmodel

| # | Angriber | Hvad vi antager | Hovedforsvar |
|---|---|---|---|
| 1 | **En narret agent** (mest sandsynligt) | Agenten læser tekst udefra og kan sende hvad som helst til Key-Box, lige så ofte den vil. | Afvis som standard, passkey på alt over niveau 1, godkendelse bundet til én anmodning. |
| 2 | **Overtaget Signal-konto eller stjålet telefon** | Angriberen kan skrive som Christian i chatten. | En chatbesked godkender intet. Kun en WebAuthn-signatur med user verification tæller. |
| 3 | **En anden proces eller enhed** | På agentmaskinen eller tailnettet: kan nå Key-Box' porte. På Key-Box-maskinen: kan læse, hvad filrettighederne tillader. | Adresselister, klientcertifikat pr. agent, egen systembruger, systemd-hærdning. |
| 4 | **Phishing** | En agent sender et link til en falsk godkendelsesside. | Passkeys er bundet til Key-Box' domæne. En anden side kan ikke få en gyldig signatur. |
| 5 | **Gentagelse** | En gammel godkendelse eller adgang afspilles igen. | Engangs-challenge, én godkendelse pr. anmodning, 5 minutters udløb, adgang udleveres én gang. |

Uden for modellen: en angriber med root på Key-Box-maskinen (se
[Kendte begrænsninger](#kendte-begrænsninger)).

## Sådan håndhæves kravene

### 1. Ingen adgang uden passkey-godkendelse

- Niveau 2 og 3 går kun fra *afventer* til *klar* gennem `Engine::approve`, og
  den kaldes kun, efter en WebAuthn-signatur er verificeret: signatur, origin,
  RP ID-hash, og at flaget **UV** (user verification) er sat.
- Verifikationen er Key-Box' egen, snævre kode oven på `ring`
  (`keybox-webauthn`): kun ES256, ingen attestation, ingen udvidelser.
- Agent-API'et har intet kald, der godkender. Godkendelse findes kun på
  HTTPS-siden.
- Det samme gælder nødstop, genstart efter nødstop og ny policy: de kræver
  hver en signatur over en challenge lavet til netop det formål.
- **En ny passkey kræver et engangs-token fra serverens konsol.** En passkey
  kan ikke tilføje en anden. Ellers kunne den, der har én stjålet enhed, selv
  lave "passkey nummer to" og springe ventetiden på niveau 3 over.

### 2. Én godkendelse = én bestemt anmodning

- Hver anmodning har en **binding**: anmodnings-id, niveau, kunde, system,
  handling, mål og (for deploy) commit eller digest, hvert felt med længde
  foran, så to forskellige anmodninger aldrig giver samme bytes.
- Challengen er `SHA-256(engangstal ‖ binding)` og laves af Key-Box ud fra dens
  egen kopi af anmodningen. Browseren kan ikke bestemme, hvad der underskrives.
- En challenge kan besvares én gang, rigtigt eller forkert, og udløber efter
  2 minutter. En anmodning udløber efter 5 minutter uden godkendelse, og en
  godkendt adgang efter 5 minutter uden hentning.

### 3. Adgange er smalle og kortlivede

- **GitHub:** installationstoken til ét repo med policyens rettigheder, én
  time. Key-Box læser GitHubs svar efter; et token, der dækker mere end bedt
  om, tilbagekaldes og udleveres ikke.
- **SSH:** certifikat til agentens egen nøgle, for ét brugernavn, kun fra
  agentmaskinens adresse, højst 30 minutter, uden videresendelse, og låst til
  én kommando med den godkendte commit, hvor policyen siger det.
- Adgangen udleveres ved første hentning og gemmes ikke. Kun den agent, der
  bad om den, kan hente den; andre får "ukendt anmodning".

### 4. Faste nøgler forlader aldrig Key-Box

- GitHub App-nøglen og SSH-CA-nøglerne ligger i Vaultwarden. Key-Box henter
  én ved navn, når den skal bruges, underskriver med den og beholder den ikke.
- Værdien ligger i hukommelse, der nulstilles, i en type uden `Debug` og
  `Clone`.
- Nøgler, der ikke kan gøres kortlivede (webhotel, DNS, registrar), kræver en
  proxy, hvor Key-Box selv udfører kaldet. **Den er ikke bygget.** Sådanne
  handlinger kan derfor ikke stå i policyen endnu.

### 5. Afvis som standard

- En anmodning afvises, medmindre kunde, system, handling og mål står ordret i
  policyen, og agenten er nævnt for handlingen.
- Input valideres mod en fast grammatik og derefter mod policyen. Intet
  "saniteres". Ukendte felter er en fejl, overalt.
- **Policyen er filer, én pr. kunde, men filerne er kun et forslag.** Key-Box
  kører på den senest godkendte policy, som den gemmer selv. En ændring vises
  i ord på siden og gælder først efter en signatur over en hash af netop de
  filer. Åbne anmodninger, den nye policy ikke tillader, tilbagekaldes.

### 6. Log alt, men aldrig hemmeligheder

- Hver hændelse er en linje i en fil, der kun tilføjes til. Linjen indeholder
  SHA-256 af den forrige; `keyboxd verify-log` gennemgår kæden, og Key-Box
  starter ikke på en log, der ikke holder.
- En logværdi kan kun laves af tal, validerede id'er, faste ord, hashes og
  agentens begrænsede fritekst. Der findes ingen konvertering fra en vilkårlig
  streng, så et token kan ikke logges ved en fejl.
- Fejlbeskeder er faste ord og gengiver aldrig input.
- Tilstand gemmes før log, og log før svar.

### 7. Nødstop

- Én signatur sætter Key-Box i stop: alt åbent tilbagekaldes, alt afvises.
- Stoppet overlever en genstart.
- GitHub App'en suspenderes, så udleverede tokens dør straks. Kan GitHub ikke
  nås, siger siden det med rødt.
- SSH-certifikater kan ikke trækkes tilbage; se begrænsninger.

### 8. Notifikationer

Key-Box giver telefonen besked, når en anmodning på niveau 2 eller 3 eller en
ny policy venter. Det er Web Push: browseren på telefonen får en adresse hos
Googles push-tjeneste, og Key-Box sender en krypteret besked dertil.

- **En notifikation godkender intet.** Den indeholder ingen adresse; et tryk
  åbner altid Key-Box' egen side, hvor alt stadig kræver passkey.
- **Indholdet er Key-Box' egne data:** niveau, kunde, handling, mål og agentens
  navn. Agentens fritekst er aldrig med.
- **At tilmelde en browser kræver passkey,** og signaturen dækker netop den
  browsers adresse og nøgler. At framelde kræver browserens egen adresse, som
  kun den browser har.
- **Key-Box sender kun til Googles push-tjeneste** (`fcm.googleapis.com` og
  `jmt17.google.com`). En tilmelding med en anden adresse afvises, så ingen
  kan få Key-Box til at kalde en adresse efter eget valg.
- **Google kan ikke læse beskeden** (RFC 8291, kryptering til browserens
  nøgle). Google ser, at Key-Box sendte noget, hvornår, og til hvilken enhed.
- Browserens adresse er en hemmelighed: den logges og vises aldrig, kun en hash.
- Flere beskeder inden for 3 sekunder bliver til én, så en agent i ring ikke
  kan oversvømme telefonen.
- Krypteringen er Key-Box' egen kode oven på `ring`, prøvet mod eksemplet i
  RFC 8291 og mod Googles rigtige tjeneste.

## Niveauer

| Niveau | Godkendelse | Håndhævelse |
|---|---|---|
| 1 | Ingen; logges | Klar straks. Skal stadig stå i policyen. |
| 2 | Én passkey | Klar straks efter signaturen. |
| 3 | Passkey + 10 minutters ventetid, som kan annulleres – eller to forskellige passkeys | Ventetiden tælles af Key-Box og overlever en genstart. Samme passkey to gange tæller ikke. |

Agenter sender aldrig mails til kunder. Key-Box har ingen handling, der gør det.

## Hvem kan nå hvad

| Indgang | Hvem kan forbinde | Hvad kræves derefter |
|---|---|---|
| Agent-API (TLS 1.3, port 8443) | Adresser på `KEYBOX_AGENT_ALLOW` | Klientcertifikat, som skal ligge i `agents/` |
| Godkendelsesside (TLS 1.3, port 8444) | Adresser på `KEYBOX_WEB_ALLOW` | Passkey for alt andet end at se, afvise og framelde sin egen browser fra notifikationer |

Begge lytter kun på Tailscale-adressen. At kunne forbinde beviser ingenting.

## Kendte begrænsninger

1. **Root på Key-Box-maskinen er uden for modellen.** Den deler maskine med
   Vaultwarden, som kan nås fra internettet (accepteret 11. oktober 2026).
   Root kan læse Key-Box' Vaultwarden-kodeord (`/etc/keybox/vault-password`),
   rette i `state.db` og udstede agentcertifikater.
2. **SSH-certifikater kan ikke tilbagekaldes,** og en åben session fortsætter
   efter udløb. Afbødes med kort levetid og låste kommandoer.
3. **GitHub-tokens kan ikke begrænses til en gren.** At `main` ikke kan ændres,
   skal sikres med branch protection i hvert repo.
4. **Niveau 1 er uden godkendelse.** En narret agent kan hente alt, hvad niveau
   1 tillader. Hold det snævert.
5. **Christian skal læse, hvad han godkender.** Siden viser Key-Box' egne data,
   men en skadelig, korrekt vist anmodning kan stadig godkendes.
6. **Én passkey.** Key-Box kører med kun telefonen, indtil en reserve er
   købt (valgt 11. oktober 2026). Mistes telefonen, skal en ny registreres med
   et token fra serveren.
7. **Loggen kan afkortes eller skrives helt om** af den, der kan skrive filen.
   Siden viser antal linjer og seneste hash; de bør også noteres et andet sted.
   `chattr +a` på filen forhindrer omskrivning.
8. **Agenter adskilles på certifikat.** Kører flere agenter under samme bruger,
   ser Key-Box dem som én.
9. **Ingen grænse for antal kald** ud over 5 åbne anmodninger pr. agent.
10. **Notifikationer åbner for Google.** Key-Box må nu kalde Googles adresser
    (før kun GitHubs). Google offentliggør ikke push-tjenestens adresser for
    sig, så åbningen dækker alle Googles egne. En notifikation kan udeblive
    (telefonen er slukket, Google afviser); siden viser altid alt.
11. **Koden er ikke gennemgået af andre end forfatteren.**

## Rapportering

Fejl med sikkerhedsbetydning meldes direkte til Christian, ikke i et offentligt
issue.
