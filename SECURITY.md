# Security policy

Security fixes target the current `main` branch. Older commits and feature
branches do not have a separate security maintenance commitment. Windows 10/11,
Windows Server 2016/2019/2022/2025, and Python 3.12+ are compatibility targets;
see the README for the limits of platform verification.

Report suspected vulnerabilities through GitHub's
[private vulnerability reporting](https://github.com/cgfixit/WynDoze-Shield/security/advisories/new).
Include the affected commit or version, OS/Python version, expected and actual
behavior, and minimal reproduction steps using synthetic data. Do not open a
public issue containing an exploit, real inventory, credentials, encryption
keys, or unredacted logs. Ordinary bugs without sensitive details can use issues.

Reports are reviewed on a best-effort basis; no response-time or fix-time SLA is
promised. Use the private report thread to coordinate reproduction and disclosure.

Run the scanner only on systems you own or are authorized to assess. Findings
are heuristic review prompts, not proof of compromise or a guarantee that a
host is secure. Inventory and exports can identify people and machines. Optional
command lines can contain secrets even when encrypted. The SQLite database and
plain exports are not encrypted by the application; operators must manage
access, storage protection, retention, and deletion.
