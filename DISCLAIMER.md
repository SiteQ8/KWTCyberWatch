# Disclaimer and terms of use

KWTCyberWatch is free, open-source security tooling published under the MIT License by
Ali AlEnezi (SiteQ8). By using the software, the hosted console or the published data you
accept the following.

## No warranty, no liability

The software, the website, the console and every data file are provided **"as is"**, without
warranty of any kind, express or implied, including fitness for a particular purpose,
accuracy or non-infringement. To the fullest extent permitted by law, the author is **not
liable** for any claim, damages, loss or other liability arising from the software, its
output, or any action taken or not taken in reliance on it. See the `LICENSE` file.

## Automated heuristics are not accusations

Every score, "risk level", "phishing likely" label, alert or sighting is the output of
**automated heuristics** (string similarity, keyword matching, certificate metadata,
public DNS and registration data). A flagged domain is a *candidate for review*, nothing
more. The project makes **no assertion** that any domain, certificate, organisation or
person is malicious, fraudulent or infringing. Legitimate services, security research,
parked domains and defensive registrations are expected to appear among the results.

**Verify before you act.** Blocking, takedown requests, abuse reports, public
attribution or any enforcement action must be based on your own investigation and
judgement, in line with applicable law and your organisation's policies.

## Published relay feed

The `demo/feed/` files are **observations of public Certificate Transparency data**: a
hostname in a publicly logged certificate matched a watch keyword. Certificate
Transparency logs are public by design; the feed republishes nothing that is not already
public and adds no personal data. Scores in the feed are heuristic and subject to the
paragraph above. If you believe an entry is misleading, open an issue on GitHub and it
will be reviewed; entries older than 14 days are removed automatically.

## Trademarks and brand names

Bank, telecom, government and company names, domains and Arabic keywords appear in the
brand profiles **for identification only**, so that impersonation of those organisations
can be detected. Their use does not imply endorsement, sponsorship, affiliation or any
relationship with the organisations, and all trademarks remain the property of their
respective owners. Any organisation may request that its profile be changed or removed.

## Lawful and responsible use

KWTCyberWatch performs only passive, read-only lookups of public sources (Certificate
Transparency logs, DNS-over-HTTPS, RDAP, crt.sh, URLhaus). It does not probe, scan,
connect to or interact with the flagged hosts. You are responsible for ensuring that your
use of the tool, and any actions you take on its results, comply with the laws of your
jurisdiction, including Kuwait's Cybercrime Law (No. 63 of 2015) and data-protection rules
where they apply. Do not use the tool to harass, defame or interfere with any party.

## Data and privacy

The browser console stores everything **locally** in your browser (IndexedDB and local
storage). The hosted site sets no cookies and runs no analytics or tracking. Live lookups
go directly from your browser to the public services named above under their own terms.
The analyst name you enter is stored only in your browser and only appears in files you
choose to export.

## Third-party services

Data from Google Public DNS, Cloudflare DNS, crt.sh, RDAP registries, URLhaus, OpenPhish
and other feeds is provided by those operators under their own terms and without any
warranty from this project.

## Contact

Questions, corrections and removal requests: open an issue at
<https://github.com/SiteQ8/KWTCyberWatch/issues>.
