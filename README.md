# spoofscan

**Can a stranger send mail as your domain?** That is the only question this tool exists to answer, and for most organisations the answer is yes.

`spoofscan` is a read-only auditor of the email authentication posture of a domain — SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC and DANE — plus the domains registered to impersonate it and, optionally, a message that already got through. It scores the domain 0–100, maps every finding to **ENS (RD 311/2022, Anexo II)** and **ISO/IEC 27001:2022 Annex A / 27002:2022**, and produces a self-contained bilingual (EN/ES) HTML report and a Statement of Applicability workbook.

It sends no mail, touches no mailbox and needs no credentials: everything comes from public DNS records and, where the domain publishes one, its own MTA-STS policy file. The DNS client is built on the standard library, so there is nothing to install on the machine you audit from.

*Auditor de solo lectura de la postura de autenticacion de correo de un dominio: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC y DANE, mas los dominios registrados para suplantarlo y, opcionalmente, un mensaje que ya se colo. Puntua el dominio de 0 a 100, mapea cada hallazgo al **ENS (RD 311/2022)** y a **ISO/IEC 27001:2022**, y genera un informe HTML autocontenido y bilingue y una declaracion de aplicabilidad.*

Companion to [netscan](https://github.com/mr7security/netscan), [webscan](https://github.com/mr7security/webscan) and [logscan](https://github.com/mr7security/logscan): the network, the web service, the audit trail — and now the way in.

---

## Why the verdict is about DMARC and nothing else

A perfect SPF record does not stop anyone from putting your domain in the `From:` line. SPF authenticates the envelope sender, which the recipient never sees; DKIM authenticates a signature that may belong to a different domain entirely. Only DMARC ties either of them to the address the human being reads, and only an enforcing DMARC policy tells receivers to refuse the message when they do not match.

So `spoofscan` leads with a single answer — **spoofable: yes / no** — and everything else in the report explains it.

*Un SPF perfecto no impide que nadie ponga su dominio en el `From:`. Solo DMARC vincula la autenticacion con la direccion que lee la persona, y solo una politica DMARC en aplicacion ordena rechazar el mensaje cuando no coinciden.*

## What it checks / Qué comprueba

| ID | Severity | Check | ENS | ISO 27002 |
|---|---|---|---|---|
| SPF-01 | 🟠 HIGH | No SPF record published | mp.s.1 | 5.14, 8.20 |
| SPF-02 | 🔴 CRITICAL | SPF authorises the whole internet (`+all`) | mp.s.1 | 5.14, 8.20 |
| SPF-03 | 🟡 MEDIUM | More than one SPF record (permerror) | mp.s.1 | 5.14 |
| SPF-04 | 🟠 HIGH | No closing `-all`/`~all` and no redirect | mp.s.1 | 5.14 |
| SPF-05 | 🟡 MEDIUM | More than 10 DNS lookups (permerror) | mp.s.1 | 5.14 |
| SPF-06 | 🔵 LOW | Deprecated `ptr` mechanism | mp.s.1 | 5.14 |
| SPF-07 | 🟡 MEDIUM | Include pointing at a domain with no SPF | mp.s.1 | 5.14 |
| DKI-01 | 🟡 MEDIUM | No key on the common selectors | mp.s.1, mp.com.3 | 8.24 |
| DKI-02 | 🟠 HIGH | Key shorter than 1024 bits | mp.com.3 | 8.24 |
| DKI-03 | 🔵 LOW | Selector in test mode or revoked | mp.com.3 | 8.24 |
| DKI-04 | 🔵 LOW | Key of 1024 bits (RFC 8301 recommends 2048) | mp.com.3 | 8.24 |
| DMA-01 | 🔴 CRITICAL | No DMARC record: the domain is spoofable | mp.s.1, mp.com.3 | 5.14, 8.20 |
| DMA-02 | 🟠 HIGH | `p=none`: nothing is blocked | mp.s.1, mp.com.3 | 5.14 |
| DMA-03 | 🟡 MEDIUM | Policy stops at `quarantine` | mp.s.1 | 5.14 |
| DMA-04 | 🟡 MEDIUM | No aggregate reports requested (`rua`) | mp.s.1 | 8.16 |
| DMA-05 | 🟡 MEDIUM | Policy applied to less than 100% (`pct`) | mp.s.1 | 5.14 |
| DMA-06 | 🟡 MEDIUM | More than one DMARC record | mp.s.1 | 8.16 |
| DMA-07 | 🔵 LOW | Subdomains left open (`sp=none`) | mp.s.1 | 5.14 |
| DMA-08 | 🟡 MEDIUM | External report destination not authorised | mp.s.1 | 8.16 |
| TRA-01 | 🟡 MEDIUM | No MTA-STS policy | mp.com.2 | 8.21, 8.24 |
| TRA-02 | 🔵 LOW | MTA-STS still in `testing` mode | mp.com.2 | 8.24 |
| TRA-03 | 🔵 LOW | No TLS-RPT reporting | mp.com.2 | 8.16 |
| TRA-04 | 🟡 MEDIUM | Zone not signed with DNSSEC | mp.com.3 | 8.21 |
| TRA-05 | 🔵 LOW | No DANE (TLSA) records for the MX | mp.com.2 | 8.24 |
| TRA-06 | 🟡 MEDIUM | MTA-STS announced but the policy is unusable | mp.com.2 | 8.21, 8.24 |
| MX-01 | 🟡 MEDIUM | Non-mail domain not marked as such (null MX) | mp.s.1 | 5.14 |
| LKA-01 | 🟠 HIGH | Similar registered domain that can send mail | mp.s.1, op.mon.3 | 5.14 |
| LKA-02 | 🟡 MEDIUM | Similar registered domain without mail | op.mon.3 | 5.14 |
| EML-01 | 🟠 HIGH | Message failed DMARC and was delivered | mp.s.1, op.exp.7 | 5.26 |
| EML-02 | 🟠 HIGH | Neither SPF nor DKIM authenticated the sender | mp.s.1, op.exp.7 | 5.26 |
| EML-03 | 🟡 MEDIUM | Display name contains a different address | mp.s.1 | 5.14 |
| EML-04 | 🟡 MEDIUM | `Reply-To` points at another domain | mp.s.1 | 5.14 |
| EML-05 | 🟡 MEDIUM | Risky attachments (executable, macro, double extension) | op.exp.6 | 8.7 |
| EML-06 | 🔵 LOW | Suspicious links (IP literal, punycode, deep subdomain) | mp.s.1 | 5.14 |
| EML-07 | ⚪ INFO | No trustworthy `Authentication-Results` | op.exp.7 | 5.26 |
| EML-08 | 🟡 MEDIUM | Sender identities do not match the visible `From` | mp.s.1, op.exp.7 | 5.26 |

Severity weights feed the score: CRITICAL −40, HIGH −20, MEDIUM −10, LOW −4, INFO 0, floored at 0. Every finding cites the clause it rests on — an RFC section for the technical rules, an ENS requirement where one applies — so the report can be defended line by line.

## Install

```bash
git clone https://github.com/mr7security/spoofscan.git
cd spoofscan
pip install -r requirements.txt     # only needed for the Excel SoA
# optional, for the `spoofscan` command:
pip install -e .
```

Requires Python 3.9+. The audit itself uses the standard library only.

## Usage / Uso

```bash
# Audit one domain -> writes report.html
python -m spoofscan example.org

# Several domains, with a comparative table in the console
python -m spoofscan example.org example.com --domains-file dominios.txt

# Full evidence package
python -m spoofscan example.org -o informe.html --json resultados.json \
    --soa declaracion.xlsx --posture evidencia.json

# Explain why a message got through
python -m spoofscan example.org --eml sospechoso.eml --authserv-id mx.example.org

# Faster: DNS only, no impersonation search, specific resolver
python -m spoofscan example.org --no-lookalike --no-mta-sts-fetch --resolver 9.9.9.9

# Probe the DKIM selectors your provider actually uses
python -m spoofscan example.org --selectors s1,s2,corporativo

# Re-evaluate archived evidence without touching DNS again
python -m spoofscan --from-posture evidencia.json -o informe-revisado.html
```

### Options

| Flag | Description |
|---|---|
| `-o, --output` | HTML report path; with several domains it is used as a prefix |
| `--domains-file` | Read domains from a file, one per line |
| `--eml PATH` | Also analyse a received message |
| `--authserv-id ID` | Identifier of your own gateway, so only the header it wrote is trusted |
| `--selectors LIST` | DKIM selectors to probe instead of the defaults |
| `--no-lookalike` | Skip the search for similar registered domains |
| `--lookalike-limit N` | Cap the number of candidates tested (default 400) |
| `--no-mta-sts-fetch` | Do not fetch the MTA-STS policy over HTTPS |
| `--resolver IP` | DNS server to use; repeat for several |
| `--timeout SECONDS` | DNS timeout (default 5) |
| `--json [PATH]`, `--soa [PATH]`, `--posture PATH` | Machine readable outputs and evidence |
| `--from-posture PATH` | Re-evaluate a saved posture |
| `--lang {en,es}`, `--quiet`, `--no-report` | Output control |

Exit codes: `0` clean or only low/medium findings, `2` at least one HIGH or CRITICAL, `1` execution error. Handy as a CI gate or a scheduled drift check on your own domains.

## Output / Salida

- A console verdict: spoofable yes/no, score, how many checks could be evaluated, findings and control status.
- A self-contained bilingual HTML report with the verdict banner, per-finding recommendation, the table of similar registered domains, **the DNS records to publish**, and an EN/ES toggle. No external assets, prints cleanly to PDF.
- An Excel **Statement of Applicability**: one row per control with status, justifying findings, evidence and empty owner / target-date columns, so it doubles as the remediation plan.
- JSON for pipelines, and a raw posture file for evidence archival.

## Project structure

```
spoofscan/
├── spoofscan/
│   ├── cli.py             # argument parsing + orchestration
│   ├── dns.py             # minimal DNS client on the standard library
│   ├── collector.py       # read-only collection for one domain
│   ├── spf.py             # SPF parsing and lookup counting (RFC 7208)
│   ├── dkim.py            # DKIM key records and key size (RFC 6376)
│   ├── dmarc.py           # DMARC tags and report authorisation (RFC 7489)
│   ├── lookalike.py       # impersonation candidate generation
│   ├── eml.py             # forensic reading of a received message
│   ├── checks.py          # all rules (pure, unit-tested)
│   ├── catalog.py         # ENS / ISO control catalogue and cross-mapping
│   ├── models.py          # Finding, Severity, Status, bilingual text helper
│   ├── scoring.py         # score, spoofability verdict, control status
│   ├── report_html.py     # self-contained bilingual HTML report
│   ├── report_soa.py      # Statement of Applicability workbook
│   └── report_console.py  # console report and multi-domain table
└── tests/                 # offline tests: wire format, parsers, rules, reports
```

```bash
python -m unittest discover -s tests
```

The tests build DNS responses byte by byte and parse sample messages, so the whole suite runs with no network at all.

## Scope and honesty about it / Alcance

A field that could not be resolved is treated as *not determinable*: it never produces a finding, and the controls it would have covered are reported as **NOT ASSESSED** rather than counted as a pass. Every report states how many of the applicable checks were actually evaluated, so a good score built on very little evidence is visible instead of flattering.

Three limits worth stating plainly. DKIM selectors cannot be enumerated from DNS, so finding no key proves only that the common selectors are unused — pass the real ones with `--selectors`. The DNSSEC verdict depends on the resolver: the AD flag only means something when the resolver validates. And an `Authentication-Results` header is only evidence if your own gateway wrote it, since anyone can add one: pass `--authserv-id` and the tool will trust nothing else, and say so when it cannot tell.

A domain whose DNS never answered gets no score at all rather than a clean 100 — absence of evidence is not evidence of absence, and every report says how many checks actually ran.

*Un dato que no se ha podido resolver se trata como no determinable: no genera hallazgo y los controles que habria cubierto se informan como NO EVALUADO. Los selectores DKIM no se pueden enumerar desde el DNS, asi que no encontrar clave solo prueba que no se usan los selectores habituales.*

## Legal notice / Aviso legal

This tool queries public DNS records, which is not an attack, but the lookalike search generates hundreds of queries and the results are about third parties. Audit domains you own or are authorised to assess, and treat the list of similar domains as a lead to investigate, not as an accusation: many are registered defensively, by resellers, or by someone with a legitimate claim to the name.

*Esta herramienta consulta registros DNS publicos, lo que no constituye un ataque, pero la busqueda de dominios parecidos genera cientos de consultas y los resultados hablan de terceros. Audite dominios propios o con autorizacion, y trate la lista de dominios similares como una pista que investigar, no como una acusacion.*

## License

MIT — see [LICENSE](LICENSE).
