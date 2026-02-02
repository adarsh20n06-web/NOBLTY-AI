==================================================
          Security Policy for NOBLTY AI × aastrax
==================================================

SUPPORTED VERSIONS
------------------
All officially released versions of NOBLTY AI × aastrax are supported.

REPORTING A VULNERABILITY
-------------------------
If you discover a security vulnerability, please report it PRIVATELY to the owner:

- Email:nobltyaastrax@gmail.com
- Subject: "[Security] Vulnerability Report"

Do NOT publicly disclose security issues.

SECURITY GUIDELINES FOR DEPLOYMENT
----------------------------------
1. Always use strong, unique secrets for:
   - SESSION_SECRET
   - OWNER_SECRET
   - OAuth client secrets
2. Ensure database and Redis are not publicly exposed
3. Keep dependencies up-to-date
4. Use HTTPS in production
5. Restrict access to training endpoints to the owner only
6. Monitor logs for suspicious activity

SECURITY BEST PRACTICES
-----------------------
- Do not hardcode secrets in the codebase
- Do not commit .env files to version control
- Use environment variables for credentials
- Regularly backup Redis and PostgreSQL data

ACKNOWLEDGEMENTS
----------------
We appreciate security researchers and contributors who responsibly report issues.

==================================================
