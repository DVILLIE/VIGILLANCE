# D'Vielle — Research Evidence Register and Engineering Findings

Version 1.0 • 10 October 2026 • Primary-source research record

## Method and evidence status

Research combined broad web discovery with targeted verification of official standards bodies, platform documentation, project-maintained specifications, source repositories and license files. Sources were chosen for authority and relevance; search-result popularity was not treated as truth. Competing documentation and unavailable pages are retained below.

This is a broad engineering review, not a claim that every page on the internet was scraped. No access controls were bypassed, no third-party scans were run and no external requests/messages were submitted. Primary-source contents were summarized selectively within copyright limits.

“Opened” means the relevant maintained page/content was retrieved and inspected in this documentation session. It does not mean every section of a long standard was read or the control was tested. “Indexed only” means discovery found official text but direct retrieval was blocked. “Prior dossier” identifies supporting research from the earlier recorded work rather than new verification.

## Research domains and decisions

| Domain | Engineering finding / disposition |
|---|---|
| Product/security lifecycle | Use final SSDF baseline; monitor draft changes separately |
| Threat modeling | Model assets, entry points, threats, mitigations and validation |
| Privileged IPC | Explicit pipe rights and OS identity; independent action authorization still required |
| Network enforcement | WFP arbitration matters; real effective behavior must match exact scope |
| Windows application control | Separate policy effectiveness, authoring tools, build and entitlements |
| Sandbox | Home lacks Windows Sandbox; use truthful unavailable state and alternative workflow |
| Resource control | Job membership/children matter; caps alone do not prove user responsiveness |
| Crash and recovery | Intent/ownership/state comparison needed across interruption and external edits |
| Dependencies | Version/commit applicability plus reachable behavior; inventory is foundational |
| Vulnerability prioritization | EPSS context differs from host-compromise probability |
| Threat feeds | Authentication, fair use and category coverage constrain integration |
| Browser/identity | Relying-party-scoped authentication addresses one layer; endpoint/session controls remain separate |
| AI authority | Narrow functionality/rights; models propose rather than authorize |
| AI poisoning/privacy | Version provenance, feedback isolation and held-out evaluation |
| Cryptographic migration | Inventory/provider capability, protocol integration and peer evidence |
| Update security | Trusted roots, freshness/version/hash checks plus protected activation |
| Build/source provenance | Check builder/material identities, not signature presence alone |
| Statistical validation | Independent populations, denominators and exact uncertainty |
| Combinatorial validation | Cover interactions and event orders, plus mandatory security cases |
| Formal verification | Check specified state models, then validate code/platform correspondence |
| Accessibility | Native control access plus relevant motion/flash principles |
| Privacy | Purpose, retention, export and actual egress must be verified |
| Incident/disclosure | Operational response and monitored reporting route required |
| Legal/distribution | Actual entity/markets/data determine applicability; free price is insufficient |
| Firmware/resilience | Independent recovery when local trust is doubtful |
| Sustainability/adoption | Free core requires maintainable operation and honest comparison |

## Source register

| ID | Primary source | Status and precise use |
|---|---|---|
| RS-01 | [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | Opened; final development framework baseline |
| RS-02 | [NIST SSDF 1.2](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) | Opened; page identifies initial public draft, dated 17 December 2025 |
| RS-03 | [OWASP threat modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | Opened; structured threat review |
| RS-04 | [OWASP SAMM](https://owasp.org/projects/samm) | Opened; software assurance organization |
| RS-05 | [OWASP ASVS](https://owasp.org/projects/asvs) | Opened; relevant web/API verification; not endpoint certification |
| RS-06 | [Windows pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) | Opened; generic-write/create-instance distinction |
| RS-07 | [WFP arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) | Opened; weights/action overrides/layers |
| RS-08 | [App Control overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol) | Opened; overview/license table lists Pro and higher |
| RS-09 | [App Control feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability) | Opened; says policies effective on all editions, authoring cmdlets unavailable on Home |
| RS-10 | [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) | Opened; explicitly unsupported on Home |
| RS-11 | [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) | Opened; child/job/breakaway accounting |
| RS-12 | [Controlled folder access](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-controlled-folders) | Official indexed discovery; configuration reference, exact-build efficacy still untested |
| RS-13 | [Microsoft UI Automation](https://learn.microsoft.com/en-us/windows/win32/winauto/microsoft-active-accessibility-and-ui-automation-compared) | Official indexed discovery; native accessibility design reference |
| RS-14 | [WCAG 2.2](https://www.w3.org/TR/WCAG22/) | Opened; relevant web accessibility/motion/flash criteria |
| RS-15 | [Animation from interactions](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions) | Opened; Level AAA explanation, not blanket native certification |
| RS-16 | [NIST Privacy Framework](https://www.nist.gov/privacy-framework) | Opened; currently surfaces 1.1 initial public draft material |
| RS-17 | [NIST adversarial ML](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) | Opened; poisoning/evasion/abuse taxonomy and correction notice |
| RS-18 | [OWASP excessive agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Opened; narrow functionality and permissions |
| RS-19 | [ML-KEM standard](https://csrc.nist.gov/pubs/fips/203/final) | Opened; final algorithm and corrections tracking |
| RS-20 | [ML-DSA standard](https://csrc.nist.gov/pubs/fips/204/final) | Opened; authentication/signature family and corrections |
| RS-21 | [NIST KEM integration](https://csrc.nist.gov/pubs/sp/800/227/final) | Opened; final integration guidance |
| RS-22 | [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) | Opened; cryptographic inventory representation |
| RS-23 | [TUF specification 1.0.36](https://theupdateframework.github.io/specification/v1.0.36/) | Opened; metadata/version/freshness/root process |
| RS-24 | [SLSA 1.2 provenance](https://slsa.dev/spec/v1.2/provenance) | Opened; source/build provenance |
| RS-25 | [OpenSSF Scorecard](https://openssf.org/scorecard/) | Opened; repository hygiene signals |
| RS-26 | [OSV API](https://google.github.io/osv.dev/api/) | Opened; version/commit lookup; current rate/response-size documentation |
| RS-27 | [FIRST EPSS data](https://www.first.org/epss/data.html) | Opened; free lookup API and bulk CSV distinction |
| RS-28 | [ZAP automation](https://www.zaproxy.org/docs/automate/automation-framework/) | Official indexed discovery; optional assessment orchestration |
| RS-29 | [ZAP scope](https://www.zaproxy.org/docs/desktop/start/features/scope/) | Opened; context/scope reference |
| RS-30 | [ZAP legal notice](https://github.com/zaproxy/zaproxy/blob/main/LEGALNOTICE.md) | Opened; Apache core plus mixed third-party package obligations |
| RS-31 | [osquery license](https://github.com/osquery/osquery/blob/master/LICENSE) | Opened; Apache-2.0 OR GPL-2.0-only repository declaration |
| RS-32 | [Atomic Red Team license](https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt) | Opened; MIT; tests still require authorization |
| RS-33 | [Sysinternals FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq) | Opened; use is free, redistribution is not authorized |
| RS-34 | [URLhaus community API](https://urlhaus.abuse.ch/api/) | Opened; Auth-Key and fair-use conditions |
| RS-35 | [abuse.ch terms](https://abuse.ch/terms-of-use/) | Opened; usage conditions must fit actual project model |
| RS-36 | [Safe Browsing appropriate use](https://developers.google.com/safe-browsing/reference/Appropriate.Usage) | Opened; non-commercial restriction and quotas |
| RS-37 | [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) | Opened; Recommendation 25 August 2026, scoped credential standard |
| RS-38 | [NIST ACTS](https://csrc.nist.gov/Projects/Automated-Combinatorial-Testing-for-Software) | Opened; public-domain interaction coverage tooling |
| RS-39 | [NIST exact binomial](https://itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm) | Opened; confidence-bound methods |
| RS-40 | [TLA+ Toolbox](https://lamport.azurewebsites.net/tla/toolbox.html) | Opened; state-model tooling |
| RS-41 | [NIST incident response](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Opened; final revision 3 |
| RS-42 | [NIST firmware resilience](https://csrc.nist.gov/pubs/sp/800/193/final) | Opened; platform protection/detection/recovery |
| RS-43 | [NIST cyber resilience](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final) | Opened; resilience engineering |
| RS-44 | [CISA 2026 disclosure bulletin](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/420a485) | Opened; announces joint guidance 15 July 2026 |
| RS-45 | [CISA disclosure guidance](https://www.cisa.gov/resources-tools/resources/establishing-coordinated-vulnerability-disclosure-program-work-security-researchers) | Direct page 403; full guidance not reviewed here |
| RS-46 | [GDPR official text](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng) | Official indexed discovery; canonical open hit anti-bot page |
| RS-47 | [Cyber Resilience Act official PDF](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32024R2847) | Official 81-page PDF retrieved after canonical page hit anti-bot; not a completed project applicability determination |
| RS-48 | [PQC migration project](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) | Prior dossier; discovery/interoperability workstreams |
| RS-49 | [Microsoft PQC announcement](https://blogs.windows.com/windowsexperience/2025/11/18/ignite-2025-windows-at-the-frontier-of-work/) | Prior dossier; capability announcement still requires exact-build/consumer verification |

## Findings that changed the design

1. App Control documentation separates effective policies from Home authoring tools while another overview's support/licensing table is narrower. The design records this discrepancy and requires actual capability/rights validation.
2. EPSS API is intended for individual/small-batch lookup; bulk synchronization belongs on CSV. This changes the enrichment architecture.
3. URLhaus is not an unconditional anonymous free feed. Auth-Key and actual use conditions matter. It remains optional.
4. Safe Browsing's non-commercial restrictions cannot be inferred satisfied merely because users pay nothing. It is excluded as a compulsory dependency.
5. ZAP's core license is not the full package license inventory; osquery currently has a dual-license declaration.
6. WebAuthn Level 3 is a Recommendation in the fetched current text. Earlier draft assumptions would be stale.
7. A five-second lightning interval does not establish flash safety within a burst. Animation acceptance needs actual analysis.
8. Standards/draft status and correction notices must be part of release engineering, not one-time research.

## Questions requiring additional evidence

Literature provides candidate mechanisms. Actual source/runtime and experiments must settle trusted approval mediation, target binding, containment semantics, provider interoperability, accessibility bridge support and measured resource budgets. Legal applicability additionally requires entity/market/data-flow facts and review of relevant official provisions. The CRA PDF access obstacle was resolved; GDPR direct retrieval remained unavailable here.

Each has a proposed resolution and proof obligation in [Engineering Resolution Dossier](22_Engineering_Resolution_Dossier.md). No implementation/field superiority is claimed from this register. Continue research against specific contradictory evidence or new counterexamples; do not manufacture completeness by adding irrelevant links.
