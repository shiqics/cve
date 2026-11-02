# Dolibarr 24.0.2 — Security Advisories

Public advisories for vulnerabilities found in Dolibarr ERP & CRM 24.0.2.

| Advisory | Component | Class | Authentication | Severity | Affected |
|---|---|---|---|---|---|
| [WebDAV arbitrary file write → unauthenticated RCE](V-01-WebDAV-Arbitrary-File-Write-to-Unauthenticated-RCE-EN.md) | `dav/fileserver.php`, sabre/dav | Auth bypass, missing authorization, path traversal, arbitrary file write, RCE | None | Critical | 24.0.2 |
| [REST API `barcode_type` SQL injection](V-13-REST-API-barcode_type-Unquoted-Numeric-SQL-Injection-EN.md) | `product/class/product.class.php` via REST API | SQL injection (error-based, cross-table read) | API key with `produit/creer` | High | 24.0.2 |

Both advisories were reproduced on a fresh installation of the official 24.0.2 release package
with only the bundled, stable modules enabled and no security hardening changes. It
contain the full data flow, annotated source, reproduction steps and proof of concept.

Product: Dolibarr ERP & CRM
Vendor: Dolibarr project — <https://github.com/Dolibarr/dolibarr>
Vendor security contact: `security@dolibarr.org`

## Reproduction environment

[Environment-Setup-Dolibarr-24.0.2.md](Environment-Setup-Dolibarr-24.0.2.md) documents how
to build the Dolibarr 24.0.2 instance used for reproduction: the official
`dolibarr/dolibarr:24.0.2` image, a fresh database, and the default installer output with
only bundled modules enabled.

## Repository layout

```
dolibarr-24.0.2/
├── README.md
├── V-01-WebDAV-Arbitrary-File-Write-to-Unauthenticated-RCE-EN.md
├── V-13-REST-API-barcode_type-Unquoted-Numeric-SQL-Injection-EN.md
├── Environment-Setup-Dolibarr-24.0.2.md
└── image/                       reference screenshots
```
