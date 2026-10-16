# Authorised security-research probe

Bugcrowd managed bug bounty `dbtlabs-mbb-og1`, safe harbour. Tag A145F9, nonce 1b2047c13a46.

Characterises whether dbt Cloud's CI Lint step shares its scratch directory
across runs. The payloads read process-local directory NAMES only, plus the
content of files this researcher planted. No environment variables, no
network calls, no instance metadata, no credentials, and no other tenant's
file content are ever read.
