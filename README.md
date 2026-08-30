# Phishing Email Analyzer

A Python tool that analyzes email headers and body text to detect common phishing tactics — mismatched sender domains, urgency/pressure language, and lookalike brand impersonation — then uses the Claude API to write up the findings as an analyst-style report. Built as my second AI-augmented SOC portfolio project, following the same approach as my [SSH Log Triage Tool](https://github.com/frashid24/ssh_triage_project): rule-based detection first, AI layered on top second.

I picked this as a different domain on purpose (email/social engineering instead of host logs) to show some range instead of just building on the same skill twice.

## What it does

`PhishingAnalyzer` takes a path to an email file and runs three checks:

1. **Domain mismatch (`check_domain`)** — compares the `From` domain against the `Reply-To` domain. Legitimate senders almost always match; phishing emails frequently don't, since replies route back to the attacker's own address.
2. **Urgency/pressure language (`check_urgency`)** — scans the email body for a curated list of phrases commonly used to create false urgency ("act now," "24 hours," "suspended," "final notice," etc.).
3. **Lookalike brand detection (`check_lookalike`)** — checks the sender domain against a list of the most commonly impersonated brands (researched from real phishing report data: Microsoft, LinkedIn, Google, Apple, Amazon, ChatGPT, PayPal, Netflix, Facebook), with a normalization step that catches character-substitution tricks like `paypa1-support.com` impersonating `paypal.com`.

`ReportGenerator` then takes the results of all three checks and sends them to the Claude API, which returns a short, human-readable phishing analysis report.

## Sample output

```
ALERT! From Domain: 'paypa1-support.com' and the Reply To Domain: 'account-verify-secure.net' do not match!
Lookalike brands detected: Brand: paypal, Real Domain: paypal.com

## Phishing Analysis Report

This email exhibits multiple high-confidence phishing indicators and should be treated
as malicious. The sending domain 'paypa1-support.com' is a clear lookalike impersonating
PayPal (paypal.com), using character substitution ("1" replacing "l") — a classic
phishing tactic. Further raising suspicion, the Reply-To domain
('account-verify-secure.net') does not match the sending domain, suggesting replies will
be redirected to a fraudulent address controlled by attackers. The email also employs
urgent language including terms like "urgent," "24 hours," "suspended," and "final
notice" — psychological pressure tactics designed to provoke hasty action from the
recipient. Do not click any links, provide credentials, or reply to this email.
```

## Why the character-substitution normalization step?

My first version of the lookalike check just looked for the brand name as a substring in the domain (e.g., is `"paypal"` in `"paypal-secure-login.com"`) — this caught domains that add extra text around a correctly-spelled brand name, but missed something like `paypa1-support.com`, since `"paypal"` (with a real `l`) never appears as a substring when the domain uses a `1` instead. Adding a normalization step that swaps common lookalike characters back before comparing closed that gap. Full edit-distance/Levenshtein comparison would catch even more cases, but felt like a bigger jump for this version — noted as a possible future upgrade.

## Why keep the AI layer in a separate class?

Same reasoning as my SSH triage tool: `PhishingAnalyzer` doesn't know or care that AI exists — it just reads an email and runs detection logic, no API key or network access required. `ReportGenerator` receives an Anthropic client and the analyzer's results as input, rather than being baked into the detection class. That keeps the core detection logic testable and reusable on its own.

## Why does `PhishingAnalyzer` take a file path instead of raw text?

My first version took an already-read email string, which meant the calling code had to manually open and read the file before creating the object. I changed `__init__` to take a file path and read the file internally instead, matching how my `LogAnalyzer` class handles `auth.log`. In a real SOC context this tool would need to process many emails, likely in a loop over a folder — having the class own its own file-reading keeps that future usage simpler and makes the two classes in my portfolio consistent with each other.

## Project structure

`PhishingAnalyzer` (one object per email file being analyzed):
- `extract_domain()` — pulls the sender's domain out of the `From` header (shared helper, since both `check_domain` and `check_lookalike` need it)
- `normalize_domain()` — builds a de-leetspeak'd version of the domain for the lookalike check
- `check_domain()` — From vs. Reply-To comparison (prints and returns the result)
- `check_urgency()` — scans body text against a phrase list (returns a list of matches)
- `check_lookalike()` — checks the normalized domain against known brand names (returns a list of matches)

`ReportGenerator`:
- `generate_summary(domain_result, urgency_result, lookalike_result)` — sends the three check results to the Claude API and returns a written phishing analysis report

```python
analyzer = PhishingAnalyzer("phishing_email_1.txt")
domain_result = analyzer.check_domain()
urgency_result = analyzer.check_urgency()
lookalike_result = analyzer.check_lookalike()

reporter = ReportGenerator(client)
summary = reporter.generate_summary(domain_result, urgency_result, lookalike_result)
print(summary)
```

## Files

- `phishinganalyzer_v2.py` — the `PhishingAnalyzer` and `ReportGenerator` classes
- `phishing_email_1.txt`, `phishing_email_2.txt` — generated sample phishing emails
- `legit_email_1.txt`, `legit_email_2.txt` — generated sample legitimate emails

## How to run

```bash
python3 phishinganalyzer_v2.py
```

You'll need your own Anthropic API key — set it as an environment variable, or if running in Colab like I did, store it in Colab's Secrets manager as `ANTHROPIC_API_KEY`.

## What I learned building this

- Extracting structured data (an email address/domain) from unstructured text using `.split()` on characters other than whitespace, plus `.strip()` to clean up leftover characters
- Why `.lower()` matters for any keyword/phrase matching — case differences will silently break an `in` check otherwise
- `.replace()` for building a normalized version of a string, and why the substitution loop has to keep reassigning the same variable it's reading from, or earlier substitutions get overwritten
- When a helper method actually earns its place — `extract_domain` is shared by two other methods, so pulling it out avoided real duplication
- The difference between `print()` (for a human watching the script run) and `return` (so other code, like the AI report layer, can actually use the result) — a method can and often should do both
- Why a method returning a list is safer than overwriting a single variable in a loop, once there's a chance of multiple matches
- Revisited an earlier design choice (`PhishingAnalyzer` taking raw text vs. a file path) after noticing it was inconsistent with my other project, and refactored it for consistency

## What's next

- Batch mode: loop over a folder of email files, print a quick verdict for each, and only call the Claude API for emails that were actually flagged by at least one rule-based check (rather than calling the API for every single email — more realistic and cost-efficient)
- Real `.eml` file parsing (this version works on plain text email files, not full email format with attachments yet)
- Explore having AI help identify emerging brand-impersonation patterns instead of relying solely on a hardcoded `known_brands` list
- Possibly extend to attachment/hash analysis down the line, tying into a planned separate threat-intel lookup tool
