# Phishing Email Analyzer

A Python tool that analyzes email headers and body text to detect common phishing tactics: mismatched sender domains, urgency/pressure language, and lookalike brand domains. Built as my second AI-augmented SOC portfolio project — same philosophy as my [SSH Log Triage Tool](https://github.com/frashid24/ssh_triage_project): show the rule-based fundamentals first, then layer AI on top in a later version.

I picked this as a different domain on purpose (email/social engineering instead of host logs) to show some range instead of just building on the same skill twice.

## What it does

The `PhishingAnalyzer` class runs three checks against an email:

1. **Domain mismatch (`check_domain`)** — compares the `From` domain against the `Reply-To` domain. Legitimate senders almost always match; phishing emails frequently don't, since the reply address routes back to the attacker.
2. **Urgency/pressure language (`check_urgency`)** — scans the email body for a curated list of phrases commonly used to create false urgency ("act now," "24 hours," "suspended," "final notice," etc.), a classic social engineering tactic.
3. **Lookalike brand detection (`check_lookalike`)** — checks the sender domain against a list of the most commonly impersonated brands (researched from real phishing report data: Microsoft, LinkedIn, Google, Apple, Amazon, ChatGPT, PayPal, Netflix, Facebook). It also normalizes common character substitutions (`1`→`l`, `0`→`o`, `3`→`e`, `5`→`s`) so it can catch tricks like `paypa1-support.com` impersonating `paypal.com`, not just domains that spell the brand name correctly.

## Sample output

```
=== phishing_email_1 ===
⚠️ ALERT! From Domain: 'paypa1-support.com' and the Reply To Domain: 'account-verify-secure.net' do not match!
Urgency matches: ['urgent', '24 hours', 'suspended', 'final notice']
⚠️ Lookalike brands detected:
Brand: paypal, Real Domain: paypal.com

=== legit_email_1 ===
✅ Domains match: brightpeak-retail.com
Urgency matches: []
✅ No lookalike brands detected.
```

## Why the character-substitution normalization step?

My first version of the lookalike check just looked for the brand name as a substring in the domain (e.g., is `"paypal"` in `"paypal-secure-login.com"`) — this worked for domains that add extra text around a correctly-spelled brand name, but completely missed something like `paypa1-support.com`, since `"paypal"` (with a real `l`) never actually appears as a substring when the domain uses a `1` instead. Adding a normalization step that swaps common lookalike characters back before comparing closed that gap. Full edit-distance/Levenshtein comparison would catch even more cases, but felt like a bigger jump for this version — noted as a possible future upgrade.

## Project structure

`PhishingAnalyzer` (one object per email being analyzed):
- `extract_domain()` — pulls the sender's domain out of the `From` header (shared helper, since both `check_domain` and `check_lookalike` need it)
- `normalize_domain()` — builds a de-leetspeak'd version of the domain for the lookalike check
- `check_domain()` — From vs. Reply-To comparison
- `check_urgency()` — scans body text against a phrase list
- `check_lookalike()` — checks the normalized domain against known brand names

```python
analyzer = PhishingAnalyzer(some_email_text)
analyzer.check_domain()
analyzer.check_urgency()
analyzer.check_lookalike()
```

## Files

- `phishing_analyzer.py` — the `PhishingAnalyzer` class
- `sample_emails.py` — four generated sample emails (two phishing, two legitimate) used to test and validate the detection logic

## How to run

```bash
python3 phishing_analyzer.py
```

No dependencies beyond the Python standard library.

## What I learned building this

- Extracting structured data (an email address/domain) from unstructured text using `.split()` on characters other than whitespace, plus `.strip()` to clean up leftover characters
- Why `.lower()` matters for any keyword/phrase matching — case differences will silently break an `in` check otherwise
- `.replace()` for building a normalized version of a string, and why the substitution loop has to keep reassigning the *same* variable it's reading from, or earlier substitutions get overwritten instead of accumulating
- When a helper method actually earns its place: `extract_domain` is shared by two other methods, so pulling it out avoided real duplication — but I intentionally *didn't* do the same for a piece of logic (the Reply-To extraction) that's only ever used in one method, since that would've just added an extra function call for no benefit
- Recognized and removed a redundant method call once I realized `normalize_domain()` already calls `extract_domain()` internally, so calling it again separately was just wasted work
- The real limitation of a simple substring check for lookalike detection, and why a hardcoded brand list + character-substitution catches more than either alone

## What's next (v2)

- Add a Claude API layer that takes the results of all three checks and writes a short analyst-style phishing risk summary, similar to my SSH triage tool's incident report
- Explore having AI help identify emerging brand-impersonation patterns instead of relying solely on a hardcoded `known_brands` list
- Real `.eml` file parsing (this version works on plain text email strings, not actual email files yet)
- Possibly extend to attachment/hash analysis down the line, tying into a planned separate threat-intel lookup tool
