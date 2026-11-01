# GitHub App til Key-Box

Key-Box laver kortlivede GitHub-tokens gennem en GitHub App. Appens private
nøgle er en fast nøgle: den ligger kun hos Key-Box og udleveres aldrig. Hvert
token gælder én time, ét repo og kun de rettigheder, policy-filen nævner.

## Opret appen

1. Organisationen → Settings → Developer settings → **GitHub Apps** →
   **New GitHub App**.
2. Udfyld:
   - **GitHub App name:** fx `IT Hjaelp Nu Key-Box` (skal være unikt på GitHub).
   - **Homepage URL:** `https://github.com/IT-Hjaelp-Nu/Key-Box`
   - **Webhook:** fjern fluebenet ved **Active**.
3. **Repository permissions** er loftet for, hvad en agent nogensinde kan få.
   Key-Box skærer ned pr. anmodning, men kan aldrig give mere:
   - **Contents:** Read and write
   - **Pull requests:** Read and write
   - **Metadata:** Read-only (sættes automatisk)
   - Alt andet: No access.
4. **Where can this GitHub App be installed?** → **Only on this account**.
   (Vælg "Any account" kun, hvis kunders egne GitHub-konti skal med.)
5. **Create GitHub App**.
6. Notér **Client ID** (begynder med `Iv`). Det er ikke hemmeligt.
7. **Private keys** → **Generate a private key**. Der hentes en `.pem`-fil.
8. **Install App** → installér på organisationen → **Only select
   repositories** → vælg kun de repoer, agenterne må røre.

## Bagefter

- Gem `.pem`-filens indhold i Vaultwarden og slet filen fra Downloads.
- Skriv appen ind i policy-filen. Navnet er også navnet på hemmeligheden:

  ```toml
  [github_apps.github-app-ithjaelpnu]
  client_id = "Iv23li..."

  [customers.KUNDE.systems.github.actions.read-code]
  level   = 1
  agents  = ["hermes"]
  targets = ["IT-Hjaelp-Nu/REPO"]
  method  = { github_app = { app = "github-app-ithjaelpnu", permissions = { contents = "read" } } }
  ```

- Slå **branch protection** til på `main` i hvert repo. Et GitHub-token kan
  ikke begrænses til en gren, så det er branch protection, der forhindrer en
  agent med skriveadgang i at ændre `main` direkte.

## Det tjekker Key-Box selv

- Den beder GitHub om et token til præcis ét repo og præcis de nævnte
  rettigheder.
- Den læser GitHubs svar. Dækker tokenet et andet repo, flere repoer, alle
  repoer eller flere rettigheder end bedt om, tilbagekalder Key-Box det hos
  GitHub og udleverer det ikke.
- Tokenet skrives aldrig i loggen.

## Rotation af nøglen

Generér en ny private key på appens side, læg den i stedet for den gamle, og
slet den gamle nøgle på GitHub. Appen kan have to nøgler samtidig, så der er
ingen nedetid.
