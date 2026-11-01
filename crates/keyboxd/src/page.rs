//! The approval page: what Christian sees.
//!
//! Everything shown comes from Key-Box' own state. Every value is escaped on
//! its way into the page, validated or not, and text written by an agent is
//! labelled as such. The page has no inline script; `app.js` is static.

use keybox_core::engine::{Awaiting, State};
use keybox_core::ident::PinKind;
use keybox_core::policy::Level;
use ring::digest::{Context, SHA256};

use crate::core::Core;
use crate::policy::Proposal;

pub const STYLE: &str = include_str!("../assets/style.css");
pub const SCRIPT: &str = include_str!("../assets/app.js");
pub const WORKER: &str = include_str!("../assets/sw.js");

/// Escape text for HTML element content and quoted attribute values.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn remaining(now: u64, at: u64) -> String {
    let secs = at.saturating_sub(now);
    format!("{} min {} sek", secs / 60, secs % 60)
}

/// A countdown. The script keeps it moving; the number of seconds left is
/// Key-Box' own, so the phone's clock does not matter.
fn timer(out: &mut String, label: &str, now: u64, at: u64) {
    out.push_str(&format!(
        "<span class=\"timer\" data-label=\"{label}\" data-left=\"{}\">{label} {}</span>",
        at.saturating_sub(now),
        remaining(now, at)
    ));
}

fn row(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!(
        "<dt>{}</dt><dd>{}</dd>",
        escape(label),
        escape(value)
    ));
}

/// One request. `grants` is what the policy in force hands out for it;
/// `spare` is whether a second passkey exists to skip the delay with.
fn request(out: &mut String, now: u64, r: &Awaiting, grants: Option<&str>, spare: bool) {
    let level = match r.level {
        Level::One => 1,
        Level::Two => 2,
        Level::Three => 3,
    };
    let id = escape(r.id.as_str());
    let delayed = matches!(r.state, State::Delayed { .. });
    out.push_str(&format!(
        "<article class=\"card request level-{level}\"><div class=\"card-top\">\
         <span class=\"badge\">Niveau {level}</span>"
    ));
    match r.state {
        State::Pending { expires_at } => timer(out, "Udløber om", now, expires_at),
        State::Delayed { ready_at } => timer(out, "Frigives om", now, ready_at),
        _ => {}
    }
    out.push_str(&format!(
        "</div><h3>{} · {}</h3><p class=\"target\">{}</p>",
        escape(r.spec.customer.as_str()),
        escape(r.spec.action.as_str()),
        escape(r.spec.target.as_str())
    ));
    if delayed {
        out.push_str(
            "<p class=\"note\">Godkendt. Adgangen frigives, når ventetiden er gået. \
             Du kan annullere indtil da.</p>",
        );
    } else if level == 3 {
        out.push_str(
            "<p class=\"note\">Niveau 3: efter din godkendelse venter Key-Box 10 minutter, \
             hvor du kan annullere.</p>",
        );
    }
    if let Some(grants) = grants {
        out.push_str(&format!(
            "<p class=\"grants\"><span class=\"label\">Giver:</span> {}</p>",
            escape(grants)
        ));
    }
    out.push_str(&format!(
        "<p class=\"agent-text\"><span class=\"label\">Skrevet af agenten:</span> {}</p><dl>",
        escape(r.reason.as_str())
    ));
    row(out, "Kunde", r.spec.customer.as_str());
    row(out, "System", r.spec.system.as_str());
    row(out, "Handling", r.spec.action.as_str());
    row(out, "Mål", r.spec.target.as_str());
    if let Some(pin) = &r.spec.pin {
        let label = match pin.kind() {
            PinKind::Commit => "Commit",
            PinKind::Digest => "Digest",
        };
        row(out, label, pin.as_str());
    }
    row(out, "Agent", r.agent.as_str());
    row(out, "Id", r.id.as_str());
    out.push_str("</dl><div class=\"actions\">");
    if !delayed {
        out.push_str(&format!(
            "<button data-act=\"approve\" data-request=\"{id}\">Godkend med passkey</button>"
        ));
    } else if spare {
        out.push_str(&format!(
            "<button data-act=\"approve\" data-request=\"{id}\">Frigiv nu med en anden passkey</button>"
        ));
    }
    let close = if delayed { "Annullér" } else { "Afvis" };
    out.push_str(&format!(
        "<button class=\"secondary\" data-act=\"cancel\" data-request=\"{id}\">{close}</button>\
         </div></article>"
    ));
}

fn short(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// A proposal waiting in the policy files: it needs Christian, so it is
/// shown with the requests.
fn proposal(out: &mut String, proposal: &Proposal) {
    let Proposal::Pending { hash, changes, .. } = proposal else {
        return;
    };
    out.push_str(&format!(
        "<article class=\"card request policy\"><div class=\"card-top\">\
         <span class=\"badge\">Policy</span></div><h3>Ny policy venter på dig</h3>\
         <p>{} ændringer. Intet af det gælder, før du godkender. Hash <code>{}</code>.</p>",
        changes.len(),
        short(hash)
    ));
    if changes.is_empty() {
        out.push_str(
            "<p>Filerne er ændret, men ingen regler er. Det er kun kommentarer, \
             rækkefølge eller filnavne.</p>",
        );
    }
    out.push_str("<ul class=\"changes\">");
    for change in changes {
        let (kind, class) = match (&change.before, &change.after) {
            (None, _) => ("Ny", "added"),
            (_, None) => ("Fjernes", "removed"),
            _ => ("Ændres", "changed"),
        };
        out.push_str(&format!(
            "<li class=\"{class}\"><strong>{kind}: {}</strong>",
            escape(&change.what)
        ));
        if change.lower_level {
            out.push_str(" <span class=\"warn\">Kræver mindre godkendelse end før.</span>");
        }
        if let (Some(before), Some(_)) = (&change.before, &change.after) {
            out.push_str(&format!(
                "<br><span class=\"label\">Før:</span> {}",
                escape(before)
            ));
        }
        if let Some(after) = &change.after {
            out.push_str(&format!(
                "<br><span class=\"label\">Nu:</span> {}",
                escape(after)
            ));
        }
        out.push_str("</li>");
    }
    out.push_str(
        "</ul><div class=\"actions\"><button data-act=\"policy\">Godkend ny policy med passkey\
         </button></div></article>",
    );
}

/// The policy in force, rule by rule, and what is wrong with the files if
/// they cannot be approved.
fn policy(out: &mut String, core: &Core, proposal: &Proposal) {
    out.push_str("<section><h2>Policy</h2>");
    match proposal {
        Proposal::Unreadable => out.push_str(
            "<p class=\"status stopped\">Policy-mappen kan ikke læses. Key-Box kører videre på \
             den godkendte policy.</p>",
        ),
        Proposal::Invalid(problem) => out.push_str(&format!(
            "<p class=\"status stopped\">Policy-filerne har en fejl og kan ikke godkendes: {} \
             Key-Box kører videre på den godkendte policy.</p>",
            escape(problem)
        )),
        _ => {}
    }
    out.push_str(&format!(
        "<div class=\"card\"><p>I kraft: {} handlinger, hash <code>{}</code>.</p>\
         <details><summary>Vis reglerne</summary><ul class=\"rules\">",
        core.loaded.actions().count(),
        short(&core.policy_hash())
    ));
    for (what, (text, level)) in crate::policy::describe(&core.loaded) {
        out.push_str(&format!(
            "<li class=\"level-{level}\"><strong>{}</strong><br>{}</li>",
            escape(&what),
            escape(&text)
        ));
    }
    out.push_str("</ul></details></div></section>");
}

/// A mark of everything the page shows that can change by itself. It says
/// that something changed, never what.
pub fn version(core: &mut Core, now: u64) -> String {
    let mut context = Context::new(&SHA256);
    let mut part = |bytes: &[u8]| {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    };
    part(core.log.head().hash.as_bytes());
    part(&[u8::from(core.engine.is_stopped())]);
    part(&(core.passkeys.list().len() as u64).to_be_bytes());
    part(core.push_marks().join(",").as_bytes());
    for r in core.engine.awaiting_approval(now) {
        part(r.id.as_str().as_bytes());
        part(&[u8::from(matches!(r.state, State::Delayed { .. }))]);
    }
    match core.proposal() {
        Proposal::Same => part(b"same"),
        Proposal::Unreadable => part(b"unreadable"),
        Proposal::Invalid(problem) => part(problem.as_bytes()),
        Proposal::Pending { hash, .. } => part(&hash),
    }
    context.finish().as_ref()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Notifications for the browser the page is open in. Which state that
/// browser is in only the script can tell; the server says how many devices
/// are subscribed and gives the marks to recognise this one by.
fn notifications(out: &mut String, core: &mut Core) {
    let marks = core.push_marks();
    let Some(key) = core.push_public_key() else {
        return;
    };
    out.push_str(&format!(
        "<section><h2>Notifikationer</h2><div class=\"card\" id=\"notify\" data-key=\"{}\" \
         data-known=\"{}\"><p id=\"notify-state\">{}</p>\
         <div class=\"actions\"><button data-act=\"notify-on\">Slå til på denne enhed</button>\
         <button class=\"secondary\" data-act=\"notify-off\" hidden>Slå fra her</button></div>\
         <p class=\"hint\">Key-Box giver besked, når en anmodning eller en ny policy venter på \
         dig. Beskeden nævner niveau, kunde, handling og mål, aldrig agentens egen tekst, og \
         den kan ikke godkende noget. At slå til kræver passkey.</p></div></section>",
        escape(&key),
        escape(&marks.join(",")),
        match marks.len() {
            0 => "Slået fra.".to_owned(),
            1 => "Slået til på 1 enhed.".to_owned(),
            n => format!("Slået til på {n} enheder."),
        }
    ));
}

const LOGO: &str = "<svg class=\"logo\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
    <circle cx=\"8\" cy=\"12\" r=\"4.5\"/><path d=\"M12.5 12H21M17 12v3.5M20 12v2.5\"/></svg>";

/// The whole page.
pub fn render(core: &mut Core, now: u64) -> String {
    let waiting = core.engine.awaiting_approval(now);
    let stopped = core.engine.is_stopped();
    let passkeys = core.passkeys.list().to_vec();
    let head = core.log.head();
    let min = core.min_passkeys;
    let pending = core.proposal();
    let mark = version(core, now);

    let mut out = format!(
        "<!doctype html><html lang=\"da\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <title>Key-Box</title><link rel=\"stylesheet\" href=\"/style.css\"></head>\
         <body data-v=\"{mark}\"><header><div class=\"brand\">{LOGO}<h1>Key-Box</h1></div>"
    );
    if stopped {
        out.push_str("<p class=\"status stopped\">NØDSTOP er aktivt. Alt afvises.</p>");
    } else if passkeys.len() < min {
        out.push_str(&format!(
            "<p class=\"status setup\">Opsætning: {} af {min} passkeys er registreret. \
             Agenter afvises indtil da.</p>",
            passkeys.len()
        ));
    } else if passkeys.len() < 2 {
        out.push_str(
            "<p class=\"status ok\">Key-Box kører.</p><p class=\"hint\">Reserve-passkey mangler: \
             mister du denne enhed, skal en ny registreres fra serveren.</p>",
        );
    } else {
        out.push_str("<p class=\"status ok\">Key-Box kører.</p>");
    }
    // What the stop did at GitHub, and above all whether it fell short.
    let (suspended, incomplete) = (core.github_suspended(), core.github_incomplete());
    if stopped && incomplete {
        out.push_str(
            "<p class=\"status stopped\">GitHub kunne ikke lukkes helt. Tokens, der allerede er \
             udleveret, kan virke i op til en time. Suspendér appen i GitHub i hånden.</p>",
        );
    } else if stopped && !suspended.is_empty() {
        out.push_str(&format!(
            "<p class=\"status setup\">GitHub App\'en er suspenderet ({} installation). \
             Udleverede tokens virker ikke længere.</p>",
            suspended.len()
        ));
    } else if !stopped && !suspended.is_empty() {
        out.push_str(
            "<p class=\"status stopped\">GitHub App\'en er stadig suspenderet og kunne ikke slås \
             til igen. Ophæv suspenderingen i GitHub i hånden.</p>",
        );
    }
    out.push_str("</header><main><p id=\"message\" role=\"alert\"></p>");

    let count = waiting.len() + usize::from(matches!(pending, Proposal::Pending { .. }));
    out.push_str("<section><h2>Venter på dig");
    if count > 0 {
        out.push_str(&format!(" <span class=\"count\">{count}</span>"));
    }
    out.push_str("</h2>");
    if count == 0 {
        out.push_str("<p class=\"empty\">Ingen anmodninger.</p>");
    }
    for r in &waiting {
        let grants = core
            .loaded
            .method(&r.spec)
            .map(|method| crate::policy::grants(method, &r.spec));
        request(&mut out, now, r, grants.as_deref(), passkeys.len() > 1);
    }
    proposal(&mut out, &pending);
    out.push_str("</section>");

    out.push_str("<section><h2>Nødstop</h2><div class=\"card stop\">");
    if stopped {
        out.push_str(
            "<p>Key-Box afviser alt lige nu.</p><div class=\"actions\">\
             <button data-act=\"resume\">Slå Key-Box til igen</button></div>",
        );
    } else {
        out.push_str(
            "<p>Trækker alt tilbage og afviser alt, indtil du slår Key-Box til igen.</p>\
             <div class=\"actions\"><button class=\"danger\" data-act=\"stop\">NØDSTOP</button></div>",
        );
    }
    out.push_str("</div></section>");
    notifications(&mut out, core);
    policy(&mut out, core, &pending);

    // During set-up the form is what the page is for; afterwards it is rarely used.
    let open = if passkeys.len() < min { " open" } else { "" };
    out.push_str("<section><h2>Passkeys</h2><div class=\"card\"><ul class=\"keys\">");
    for p in &passkeys {
        let note = if p.synced {
            " (kan synkroniseres af udbyderen)"
        } else {
            ""
        };
        out.push_str(&format!("<li>{}{note}</li>", escape(p.name.as_str())));
    }
    // A new passkey always needs the token from the server's console. An
    // existing passkey cannot add one.
    out.push_str(&format!(
        "</ul><details{open}><summary>Registrér en ny passkey</summary>\
         <label>Navn på ny passkey (fx telefon eller yubikey)\
         <input id=\"passkey-name\" autocomplete=\"off\" maxlength=\"63\"></label>\
         <label>Engangs-token fra konsollen\
         <input id=\"enroll-token\" autocomplete=\"off\"></label>\
         <div class=\"actions\"><button data-act=\"register-token\">Registrér passkey</button></div>\
         <p class=\"hint\">Tokenet laves på serveren: <code>keyboxd enroll-token</code>.</p>\
         </details></div></section>"
    ));

    out.push_str(&format!(
        "</main><footer>Log: {} linjer, seneste hash <code>{}</code></footer>\
         <script src=\"/app.js\"></script></body></html>",
        head.seq,
        escape(&head.hash[..16])
    ));
    out
}
