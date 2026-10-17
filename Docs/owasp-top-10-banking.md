# OWASP Top 10:2021 --- Security Risks in Banking Web Applications

**Project:** Automated Web Application Security Assessment for Financial
Platforms\
**Document type:** Week 1 research report\
**Version:** 1.0\
**Assessment basis:** OWASP Top 10:2021\
**Scope:** General security risks relevant to banking and financial web
applications

## 1. Introduction

Banking web applications handle sensitive information and high-impact
actions, including account access, balance and transaction viewing,
beneficiary management, transfers, and profile changes. Security
weaknesses can expose customer data, enable unauthorized actions,
interrupt services, or undermine the integrity of financial
transactions.

The OWASP Top 10:2021 is an awareness document describing ten broad
categories of important web application security risks. It is useful for
organizing initial research and planning security checks, but it is not
a complete testing standard and does not prove that an application is
vulnerable. Each potential issue must be validated safely and documented
with evidence.

This report explains each category in the context of banking
applications and lists example review activities. The examples are
assessment ideas, not claims that any specific bank or lab application
contains these weaknesses.

## 2. Scope and safe-testing approach

This report focuses on risks that may affect customer-facing banking
portals, online banking APIs, and related web services. The same
category can apply differently depending on the application architecture
and business rules.

Testing should be conducted only on systems for which explicit
authorization has been granted. For this project, use a controlled local
lab such as OWASP Juice Shop or DVWA. Do not test real banking services,
customer accounts, or third-party systems without written authorization.
Use synthetic accounts and data, avoid destructive actions, and do not
collect or publish credentials, session tokens, or personal financial
information.

For each observation, record: - the affected page, feature, or
endpoint; - the test conditions and steps performed; - the expected
secure behavior; - the observed behavior and supporting evidence; - the
potential business impact; - a recommended mitigation; and - whether the
issue is confirmed, suspected, or not observed.

## 3. OWASP Top 10:2021 categories and banking relevance

### A01:2021 --- Broken Access Control

**What it means:** The application does not consistently enforce what an
authenticated or unauthenticated user is allowed to view or do.

**Why it matters in banking:** A customer must only access their own
accounts and permitted functions. Weak access control could expose
another customer's statements, allow unauthorized beneficiary changes,
or permit actions beyond a user's role.

**Example scenarios to consider:** - An account or transaction API
accepts an object identifier without verifying that it belongs to the
signed-in customer. - A customer can access staff-only administrative
functions. - A restricted operation can be performed by changing a
request or calling an endpoint directly.

**Assessment ideas:** - Review authorization checks for account,
statement, beneficiary, and transaction resources in the authorized
lab. - Compare behavior using separate synthetic test accounts, where
permitted. - Check whether server-side authorization is applied to
direct API requests, not only hidden or disabled interface controls.

**Recommended mitigations:** Deny access by default; enforce
authorization on the server for every protected request; verify resource
ownership; use least privilege; and log relevant denied or suspicious
access attempts.

### A02:2021 --- Cryptographic Failures

**What it means:** Sensitive information is not adequately protected
because encryption is missing, weak, incorrectly configured, or used
improperly.

**Why it matters in banking:** Banking systems process personal data,
authentication information, account details, and transaction records.
Exposure in transit or at rest can create privacy, fraud, and regulatory
risks.

**Example scenarios to consider:** - Sensitive traffic is transmitted
without appropriate transport encryption. - Passwords are stored in a
reversible or otherwise unsuitable form rather than using a
purpose-built password-hashing method. - Sensitive data is unnecessarily
exposed in browser storage, logs, URLs, or backups.

**Assessment ideas:** - In a controlled environment, inspect whether
sensitive pages and requests use HTTPS and whether security
configuration is appropriate for the deployment. - Review application
design and configuration for the handling of passwords, session tokens,
and sensitive records. - Check whether secrets or sensitive values
appear in URLs or application logs.

**Recommended mitigations:** Use modern, correctly configured TLS for
data in transit; use established password-hashing algorithms with unique
salts; minimize stored sensitive data; manage cryptographic keys
securely; and prevent sensitive values from appearing in logs or URLs.

### A03:2021 --- Injection

**What it means:** Untrusted input is interpreted as part of a command
or query, such as SQL, operating-system commands, or another expression
language.

**Why it matters in banking:** Injection flaws may expose customer
records, alter transaction-related data, or compromise services that
support account and payment workflows.

**Example scenarios to consider:** - Search, login, or
transaction-history input is incorporated unsafely into a database
query. - An API passes user-controlled values into a command or query
interpreter without safe handling. - A template or other interpreter
processes untrusted input as executable instructions.

**Assessment ideas:** - Review how inputs are validated and passed to
database or interpreter interfaces. - In the local lab, use
non-destructive test inputs and observe whether input is handled as data
rather than executable syntax. - Review errors for accidental disclosure
of query details, stack traces, or internal implementation information.

**Recommended mitigations:** Prefer parameterized queries and safe APIs;
validate inputs with appropriate allowlists where practical; avoid
building commands through string concatenation; apply least privilege to
service accounts; and handle errors without exposing internals.

### A04:2021 --- Insecure Design

**What it means:** Security controls are missing or insufficient because
the application's design and business logic did not adequately account
for threats.

**Why it matters in banking:** Financial workflows have business rules
that must remain valid under unusual sequences, concurrent requests, and
attempts to bypass normal user-interface steps. A technically well-coded
feature can still be insecure if its design is flawed.

**Example scenarios to consider:** - A transfer workflow does not
adequately enforce limits, authorization, or confirmation rules. - A
sensitive account change has no suitable step-up verification or
notification. - Abuse cases, fraud scenarios, or failure conditions were
not considered during design.

**Assessment ideas:** - Map the steps and trust boundaries for a
representative workflow. - Identify important business rules, such as
transfer limits, ownership, approval, and re-authentication
requirements. - Check whether those rules are enforced by trusted
server-side components rather than only by the client.

**Recommended mitigations:** Perform threat modeling; define and test
security requirements and abuse cases; enforce business rules on the
server; apply transaction limits and suitable confirmation controls; and
include security design reviews before release.

### A05:2021 --- Security Misconfiguration

**What it means:** Security settings are missing, overly permissive,
inconsistent, or incorrectly configured in the application, server,
framework, cloud environment, or related components.

**Why it matters in banking:** Misconfiguration can expose
administrative interfaces, reveal implementation details, weaken browser
protections, or make sensitive services reachable by unintended users.

**Example scenarios to consider:** - Debug mode or verbose error pages
are enabled in a production-like deployment. - Default accounts, sample
features, or unnecessary services remain enabled. - Security headers,
access restrictions, or cross-origin settings are too permissive.

**Assessment ideas:** - Review response headers and error behavior in
the authorized lab. - Check whether default pages, test routes, or
administrative interfaces are exposed. - Compare deployment settings
with a documented secure baseline.

**Recommended mitigations:** Use hardened and repeatable configuration
baselines; remove unused features and default credentials; separate
development and production settings; restrict administrative access; and
review security settings during deployment and change management.

### A06:2021 --- Vulnerable and Outdated Components

**What it means:** The application uses libraries, frameworks, servers,
or other components with known vulnerabilities, unsupported versions, or
inadequate maintenance.

**Why it matters in banking:** A vulnerable third-party component can
undermine the security of the application even when the bank's own code
is well written.

**Example scenarios to consider:** - A dependency version has a publicly
documented security vulnerability. - An unsupported framework or server
no longer receives security fixes. - Dependency updates are not reviewed
or tested in a timely manner.

**Assessment ideas:** - Inventory direct and transitive dependencies
using the project's package-management tools. - Compare component
versions with trusted advisories and vendor support information. - Check
whether dependency updates and security patches are tracked.

**Recommended mitigations:** Maintain a software component inventory;
use supported versions; monitor trusted vulnerability advisories; patch
according to risk and exposure; and test updates before deployment. A
version match alone should be reviewed in context because configuration
and exploitability affect risk.

### A07:2021 --- Identification and Authentication Failures

**What it means:** The application cannot reliably verify a user's
identity or manage authentication and sessions securely.

**Why it matters in banking:** Authentication weaknesses may allow
account takeover, unauthorized account access, or misuse of a stolen
session.

**Example scenarios to consider:** - Login protections do not adequately
resist automated guessing or credential stuffing. - Session identifiers
are not rotated appropriately after authentication or privilege
changes. - Password-reset or multi-factor authentication flows can be
bypassed or misused.

**Assessment ideas:** - Review authentication and recovery flows in a
lab using test accounts only. - Check session-cookie attributes and
session lifecycle behavior. - Review rate limiting, multi-factor
authentication, re-authentication for sensitive actions, and
invalidation after logout.

**Recommended mitigations:** Use strong authentication appropriate to
the risk; offer and enforce multi-factor authentication for sensitive
access; apply rate limiting and abuse detection; protect session cookies
with appropriate attributes; rotate and invalidate sessions correctly;
and design account recovery securely.

### A08:2021 --- Software and Data Integrity Failures

**What it means:** The application does not adequately verify the
integrity or trustworthiness of software, updates, critical data, or
serialized inputs.

**Why it matters in banking:** If an attacker can tamper with
application updates, build pipelines, business-critical data, or trusted
client/server exchanges, the integrity of financial operations may be
affected.

**Example scenarios to consider:** - A build or deployment pipeline
accepts untrusted changes without adequate review. - Software
dependencies or updates are fetched without suitable integrity
verification. - The server trusts client-supplied values for a sensitive
business decision without independent validation.

**Assessment ideas:** - Review how code and dependencies are obtained,
reviewed, built, and deployed. - Check integrity controls around updates
and release artifacts. - Identify critical values that must be
calculated or verified by the server rather than trusted from the
browser.

**Recommended mitigations:** Protect source repositories and CI/CD
pipelines; require appropriate review and access controls; verify the
integrity and provenance of dependencies and artifacts; and validate
critical financial data and decisions on trusted server-side systems.

### A09:2021 --- Security Logging and Monitoring Failures

**What it means:** Important security events are not recorded
adequately, logs are not protected, or monitoring and response processes
fail to detect suspicious activity.

**Why it matters in banking:** Timely detection and investigation are
important for identifying account takeover, suspicious transaction
attempts, unauthorized access, and abuse of administrative functions.

**Example scenarios to consider:** - Repeated failed logins or
suspicious access attempts are not recorded or alerted on. - Logs omit
important event context needed to investigate a security incident. -
Logs contain passwords, session tokens, or unnecessary sensitive
customer data.

**Assessment ideas:** - Identify which security-relevant events are
logged in the test environment. - Check whether logs provide useful
timestamps, event types, and non-sensitive identifiers. - Review access
controls, retention, alerting, and incident-response procedures where
those materials are available.

**Recommended mitigations:** Define security logging requirements;
centralize and protect logs; monitor suspicious patterns; synchronize
timestamps; establish alert triage and incident-response procedures; and
avoid logging secrets or unnecessary sensitive data.

### A10:2021 --- Server-Side Request Forgery (SSRF)

**What it means:** A server can be induced to make requests to an
unintended destination using attacker-controlled input.

**Why it matters in banking:** Depending on network placement and
permissions, SSRF may allow access to internal services or metadata
endpoints that should not be reachable from the public web application.

**Example scenarios to consider:** - A feature that fetches a URL
accepts arbitrary destinations without adequate restrictions. - A
document, image, or webhook integration follows redirects to disallowed
internal destinations. - Server-side network access controls do not
restrict unnecessary outbound requests.

**Assessment ideas:** - Identify features that fetch URLs or contact
other systems on behalf of a user. - Review URL validation, redirect
handling, DNS resolution behavior, and outbound network restrictions. -
Perform only controlled tests against systems explicitly included in the
lab scope; do not probe internal networks or metadata services without
specific authorization.

**Recommended mitigations:** Prefer allowlists of approved destinations;
block access to loopback, private, link-local, and other prohibited
address ranges as appropriate; validate resolved addresses and
redirects; restrict outbound network access; and avoid returning
internal response details to users.

## 4. Summary matrix

  -----------------------------------------------------------------------
  OWASP category          Example banking concern Main defensive focus
  ----------------------- ----------------------- -----------------------
  A01 Broken Access       A customer accesses     Server-side
  Control                 another customer's      authorization and
                          account or performs an  resource ownership
                          unauthorized action     checks

  A02 Cryptographic       Sensitive account or    Appropriate encryption,
  Failures                authentication data is  secure password
                          exposed                 hashing, and data
                                                  minimization

  A03 Injection           User input changes the  Parameterized queries
                          meaning of a database   and safe interpreter
                          query or command        APIs

  A04 Insecure Design     A financial workflow    Threat modeling and
                          can bypass important    server-enforced
                          business rules          business controls

  A05 Security            Debug features or       Hardened, reviewed
  Misconfiguration        overly permissive       configuration baselines
                          settings expose the     
                          service                 

  A06 Vulnerable and      A known vulnerable      Inventory, advisory
  Outdated Components     library is used by the  monitoring, and timely
                          application             patching

  A07 Identification and  Account takeover or     Strong authentication
  Authentication Failures weak session handling   and secure session
                                                  lifecycle

  A08 Software and Data   Untrusted updates or    Supply-chain integrity
  Integrity Failures      client-supplied values  and trusted server-side
                          are trusted             validation

  A09 Security Logging    Suspicious activity is  Protected logs,
  and Monitoring Failures not detected or         monitoring, alerting,
                          investigated            and response
                          effectively             

  A10 SSRF                A server is induced to  Destination validation
                          contact an unintended   and outbound network
                          destination             restrictions
  -----------------------------------------------------------------------

## 5. Relevance to the project scanner

The project's Python scanner is an initial, low-impact reconnaissance
and configuration-checking tool. Its findings should be treated as
indicators for manual review, not as a complete OWASP Top 10 assessment.

A lightweight scanner may be able to help identify or record some
observable signals, such as pages and forms, candidate API routes,
response headers, and certain error behaviors. Many important
risks---especially business-logic flaws, authorization decisions, secure
transaction design, cryptographic key management, software supply-chain
controls, and effective monitoring---require code/configuration review,
authenticated testing, or organizational evidence beyond a simple
crawler.

The report should therefore distinguish: - **Observed:** directly
supported by captured evidence. - **Potential concern:** an indicator
that needs validation. - **Not assessed:** outside the scanner's current
capability or not tested. - **No issue observed in this test:** the
limited test did not reveal the issue; this does not prove the
application is secure.

Do not label a category "secure" merely because the scanner did not find
a finding. Record the scanner version, target lab, date, test limits,
and evidence when presenting results.

## 6. Conclusion

The OWASP Top 10:2021 provides a practical structure for discussing
major web application security risks in a financial context. For banking
applications, access control, authentication, cryptographic protection,
injection prevention, secure business logic, and monitoring are
particularly consequential because weaknesses can affect
confidentiality, transaction integrity, customer trust, and service
availability.

This report is a research and planning document. It does not claim that
a real banking platform---or OWASP Juice Shop or DVWA---has been tested
for all ten categories. Any future findings should be based on
authorized tests, reproducible evidence, and a clear description of
limitations.

## 7. References

1.  OWASP Foundation, **OWASP Top 10:2021**: https://owasp.org/Top10/
2.  OWASP Foundation, **A01:2021 -- Broken Access Control**:
    https://owasp.org/Top10/A01_2021-Broken_Access_Control/
3.  OWASP Foundation, **A02:2021 -- Cryptographic Failures**:
    https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
4.  OWASP Foundation, **A03:2021 -- Injection**:
    https://owasp.org/Top10/A03_2021-Injection/
5.  OWASP Foundation, **A04:2021 -- Insecure Design**:
    https://owasp.org/Top10/A04_2021-Insecure_Design/
6.  OWASP Foundation, **A05:2021 -- Security Misconfiguration**:
    https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
7.  OWASP Foundation, **A06:2021 -- Vulnerable and Outdated
    Components**:
    https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
8.  OWASP Foundation, **A07:2021 -- Identification and Authentication
    Failures**:
    https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
9.  OWASP Foundation, **A08:2021 -- Software and Data Integrity
    Failures**:
    https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
10. OWASP Foundation, **A09:2021 -- Security Logging and Monitoring
    Failures**:
    https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
11. OWASP Foundation, **A10:2021 -- Server-Side Request Forgery
    (SSRF)**:
    https://owasp.org/Top10/A10_2021-Server_Side_Request_Forgery\_%28SSRF%29/

**Note:** This report uses the OWASP Top 10:2021 edition. Confirm the
edition required by your lecturer before submitting.
