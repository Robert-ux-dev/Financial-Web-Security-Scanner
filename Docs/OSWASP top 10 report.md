WEEK 1 REPORT: OWASP TOP 10 AND ITS RELEVANCE TO BANKING APPLICATIONS
Project: Automated Web Application Security Assessment for Financial Platforms
Project Area: Cybersecurity — Banking and Finance
Topic: Introduction to Web Security and OWASP Top 10 (2021)
1. Introduction
Web applications have become an important part of modern banking and financial services. Customers use online platforms to access accounts, transfer money, view transaction histories, make payments and manage personal information. Although these services provide convenience, they also introduce security risks when applications are not designed, developed and maintained securely.
The Open Worldwide Application Security Project (OWASP) is an organization that provides resources, guidance and tools for improving software security. One of its major resources is the OWASP Top 10, an awareness document that identifies important security risks affecting web applications.
The OWASP Top 10 (2021) identifies ten categories of web application security risks. Understanding these categories is important when developing security assessment tools because they help security professionals recognize weaknesses that could expose systems and their users to attacks.
The purpose of this report is to explain the ten OWASP Top 10 (2021) categories, describe their relevance to banking and financial applications, and identify measures that can help prevent or reduce the associated risks.
2. Objectives
The objectives of this report are to:
1.	Explain the purpose of the OWASP Top 10.
2.	Identify and describe the ten security risk categories in the 2021 edition.
3.	Explain how these risks could affect banking and financial applications.
4.	Identify security measures that can reduce the likelihood and impact of vulnerabilities.
5.	Establish a foundation for developing a Python-based automated web application security scanner.
3. Overview of the OWASP Top 10
The OWASP Top 10 (2021) contains the following categories:
1.	A01 — Broken Access Control
2.	A02 — Cryptographic Failures
3.	A03 — Injection
4.	A04 — Insecure Design
5.	A05 — Security Misconfiguration
6.	A06 — Vulnerable and Outdated Components
7.	A07 — Identification and Authentication Failures
8.	A08 — Software and Data Integrity Failures
9.	A09 — Security Logging and Monitoring Failures
10.	A10 — Server-Side Request Forgery (SSRF)
These categories cover different weaknesses that may arise in the design, development, configuration and operation of web applications.
4. Explanation of the OWASP Top 10 Categories
4.1 A01: Broken Access Control
Broken access control occurs when an application fails to enforce restrictions on what users are allowed to access or do. A user may be able to view another person's information, access restricted pages or perform actions beyond their assigned permissions.
Example in banking: A customer changes an account identifier in a request and gains access to another customer's transaction history because the application does not verify account ownership.
Potential impact: This could result in unauthorised disclosure of financial information, account manipulation, privacy violations or fraudulent transactions.
Prevention measures:
•	Enforce authorisation checks on the server for every protected operation.
•	Verify that users can access only resources they are permitted to use.
•	Apply the principle of least privilege.
•	Deny access by default unless permission is explicitly granted.
•	Log and investigate suspicious access attempts.
Relevance to the project: The scanner could perform authorised checks for exposed protected routes and obvious access-control weaknesses. However, confirming account ownership and role-based restrictions may require authenticated testing with multiple test accounts.
4.2 A02: Cryptographic Failures
Cryptographic failures occur when sensitive information is not adequately protected because encryption or related security controls are missing, weak or incorrectly implemented.
Example in banking: A banking application transmits confidential customer information over an unencrypted connection or stores passwords using an unsuitable method.
Potential impact: Attackers may obtain sensitive information, leading to identity theft, financial fraud or privacy breaches.
Prevention measures:
•	Use HTTPS with properly configured TLS.
•	Store passwords using an appropriate password-hashing algorithm.
•	Encrypt sensitive data when required, both in transit and at rest.
•	Manage cryptographic keys securely.
•	Avoid storing unnecessary sensitive information.
Relevance to the project: The scanner could inspect HTTPS configuration, certificate validity and selected security headers. It could also identify certain obvious indicators of insecure data handling, but it cannot reliably prove that all stored financial data is encrypted correctly through external web requests alone.
4.3 A03: Injection
Injection vulnerabilities occur when untrusted input is interpreted as part of a command or query instead of being treated strictly as data. Examples include SQL injection, operating-system command injection and cross-site scripting (XSS).
Example in banking: A poorly secured account-search feature constructs database queries directly from user input. An attacker may manipulate the input to interfere with the intended database operation.
Potential impact: Depending on the vulnerability, attackers may access or alter information, bypass application logic or execute unintended operations.
Prevention measures:
•	Use parameterised queries and prepared statements.
•	Validate input according to the expected data type and format.
•	Encode output appropriately to prevent cross-site scripting.
•	Avoid constructing commands by concatenating untrusted input.
•	Apply least privilege to database and application accounts.
Relevance to the project: The scanner could identify candidate input fields and run carefully controlled, non-destructive tests against the local Juice Shop application. Findings should be supported by evidence rather than assumptions based only on unusual responses.
4.4 A04: Insecure Design
Insecure design refers to security weaknesses that originate from missing or inadequate security requirements and design decisions. Unlike a simple coding mistake, a design flaw may exist even when the software is implemented according to its original specification.
Example in banking: A money-transfer workflow allows transfers without adequate verification, transaction limits or protection against repeated submissions.
Potential impact: Attackers may exploit weaknesses in business logic to carry out unauthorised transactions or abuse legitimate application functions.
Prevention measures:
•	Perform threat modelling during application design.
•	Define security requirements before implementation.
•	Use secure design patterns.
•	Apply transaction limits and additional verification where appropriate.
•	Test business workflows and abuse cases.
Relevance to the project: The scanner could identify some suspicious workflow behaviours, but insecure design often requires business-context analysis and manual testing. It cannot be detected reliably through generic automated checks alone.
4.5 A05: Security Misconfiguration
Security misconfiguration occurs when an application, server, database or other component is configured insecurely. Examples include unnecessary services, exposed debugging information, unsafe default settings and missing security headers.
Example in banking: A production application displays detailed error messages that reveal internal file paths, software versions or implementation details.
Potential impact: Attackers may obtain information that helps them identify further weaknesses or exploit exposed services.
Prevention measures:
•	Disable unnecessary services and features.
•	Remove development and debugging settings from production.
•	Configure security headers appropriately.
•	Apply secure default settings.
•	Keep configurations consistent and review them regularly.
Relevance to the project: The scanner could inspect HTTP response headers, identify certain information disclosures and check for selected configuration weaknesses.
4.6 A06: Vulnerable and Outdated Components
This category concerns the use of software libraries, frameworks and other components that contain known vulnerabilities or are no longer adequately maintained.
Example in banking: A financial application relies on an outdated JavaScript library with a publicly documented security vulnerability.
Potential impact: Attackers may exploit known weaknesses in the affected component, potentially compromising application data or functionality.
Prevention measures:
•	Maintain an inventory of software dependencies.
•	Update components to supported, secure versions.
•	Monitor vulnerability advisories.
•	Remove unused dependencies.
•	Test updates before deploying them to production.
Relevance to the project: The scanner could identify component versions when they are exposed and compare available dependency information against known vulnerability records. However, a version string alone does not always prove that a component is vulnerable.
4.7 A07: Identification and Authentication Failures
Identification and authentication failures occur when an application cannot reliably verify a user's identity or manage authentication securely.
Example in banking: A customer account is protected by weak authentication controls, allowing an attacker to exploit password weaknesses or an insecure session-management process.
Potential impact: Attackers may gain unauthorised access to customer accounts, private information or financial services.
Prevention measures:
•	Enforce strong authentication practices.
•	Use multifactor authentication where appropriate.
•	Implement secure session management.
•	Apply rate limits and appropriate protections against automated login attempts.
•	Provide secure password-reset procedures.
•	Store passwords using suitable password-hashing methods.
Relevance to the project: The scanner could inspect selected authentication-related behaviours, session-cookie attributes and login response patterns. Testing account takeover risks requires additional controls and careful, authorised test cases.
4.8 A08: Software and Data Integrity Failures
Software and data integrity failures occur when an application does not adequately verify the integrity or authenticity of software, updates or critical data.
Example in banking: A software deployment process accepts an unauthorised or tampered update because it does not verify the update's authenticity.
Potential impact: Malicious changes could introduce backdoors, modify application behaviour or compromise the integrity of financial records.
Prevention measures:
•	Verify software updates and packages before installation.
•	Use trusted sources for dependencies.
•	Protect software build and deployment pipelines.
•	Apply appropriate integrity checks and digital signature verification.
•	Restrict access to production changes.
Relevance to the project: The scanner could identify certain exposed integrity weaknesses, such as missing protections in observable web delivery mechanisms. A comprehensive assessment of build pipelines and data integrity generally requires access to additional systems, configurations or source code.
4.9 A09: Security Logging and Monitoring Failures
Security logging and monitoring failures occur when an application does not adequately record, monitor or alert on security-relevant events.
Example in banking: Multiple suspicious login attempts or unauthorised account-access attempts occur without generating appropriate alerts for the security team.
Potential impact: Attacks may remain undetected for longer, increasing the damage caused and making investigations more difficult.
Prevention measures:
•	Record relevant authentication and authorisation events.
•	Monitor unusual activity and suspicious patterns.
•	Protect logs against unauthorised modification.
•	Configure appropriate alerts.
•	Ensure logs do not unnecessarily expose passwords, tokens or other sensitive information.
Relevance to the project: The scanner could identify some externally observable error-handling or information-disclosure issues. Verifying whether security events are logged, monitored and escalated usually requires access to the application's logging and monitoring systems.
4.10 A10: Server-Side Request Forgery (SSRF)
Server-Side Request Forgery occurs when an application can be tricked into making requests to unintended destinations based on insufficiently validated input.
Example in banking: A server-side feature that retrieves information from a supplied URL is manipulated into requesting an internal resource that should not be accessible to the user.
Potential impact: Depending on the environment, SSRF may expose internal services, sensitive information or resources that are not directly reachable from outside the organisation.
Prevention measures:
•	Validate and restrict permitted destinations.
•	Use allowlists for trusted hosts where appropriate.
•	Block access to sensitive internal networks and metadata services.
•	Configure outbound network access restrictions.
•	Validate redirects and resolved IP addresses.
Relevance to the project: The scanner could identify candidate URL-fetching features and conduct controlled SSRF checks in a deliberately vulnerable local environment. It must avoid making requests to real internal services or external targets without authorisation.
5. Relevance of the OWASP Top 10 to Banking Applications
Banking and financial applications process sensitive personal information and support transactions that may have direct financial consequences. Security weaknesses can therefore affect confidentiality, integrity and availability.
Broken access control and authentication failures can expose customer accounts. Cryptographic failures can compromise confidential information. Injection vulnerabilities may affect databases or application logic. Security misconfiguration and outdated components can create opportunities for attackers, while insufficient logging can delay detection and investigation.
The OWASP Top 10 provides a useful foundation for identifying these risks and planning security assessments. However, it is an awareness document rather than a complete testing methodology or guarantee that an application is secure.
Financial applications require additional controls, including transaction authorisation, fraud detection, strong identity verification, appropriate monitoring and secure handling of financial data.
6. Application to the Proposed Python Scanner
The OWASP Top 10 will guide the development of the Automated Web Application Security Assessment for Financial Platforms project.
The scanner will be developed incrementally using Python and tested against OWASP Juice Shop in a controlled environment.
The planned development stages are:
1.	Identify the target's reachable pages and entry points.
2.	Discover forms, input fields and candidate API routes.
3.	Implement detection checks for selected vulnerabilities.
4.	Collect evidence supporting each finding.
5.	Assign appropriate severity ratings and explain potential impact.
6.	Generate a structured security assessment report.
7.	Test the scanner against known cases and assess false positives and missed findings.
8.	Package the scanner using Docker.
The scanner will not claim to detect every OWASP Top 10 risk automatically. Categories involving business logic, internal configuration, logging or source-code integrity may require manual verification or access to additional systems.
All testing will be restricted to the local laboratory or other explicitly authorised targets.
7. Conclusion
The OWASP Top 10 (2021) provides an important foundation for understanding common web application security risks. Its ten categories address weaknesses involving access control, cryptography, injection, design, configuration, software components, authentication, integrity, monitoring and server-side requests.
For banking and financial platforms, addressing these risks is essential to protecting customer information, maintaining the integrity of financial operations and reducing opportunities for unauthorised access.
Understanding these categories will help guide the development of the proposed Python-based security scanner. By building and testing the scanner against a deliberately vulnerable application, the project will apply web security concepts in a controlled environment and demonstrate how automated assessment can support vulnerability identification and remediation.
8. References
1.	OWASP Foundation. (2021). OWASP Top 10:2021. https://owasp.org/Top10/2021/
2.	OWASP Foundation. (n.d.). OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/
3.	OWASP Foundation. (n.d.). OWASP Juice Shop. https://owasp.org/www-project-juice-shop/

