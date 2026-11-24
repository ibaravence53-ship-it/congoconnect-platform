# CongoConnect Platform

Plateforme de verification d identite, gestion OTP, emission/revocation de jetons PKI (`cc1.`) et supervision d audit (`GET /app`).

## Architecture et adaptateurs

- **Console web (`/app`)** : creation et suivi des demandes, generation et verification OTP, gestion des jetons `cc1.` (`tokenPanel`) et visionneuse d audit filtrable (`auditPanel`).
- **Sante et observabilite** :
  - `GET /health` : expose l etat du service et le mode des adaptateurs (`redis`, `postgres`) sans fuite de secrets.
  - `GET /api/audit` : journal d audit filtrable par `event`, `outcome` et `limit` avec masquage des identifiants.
- **Jetons `cc1.`** :
  - `POST /api/token/issue` : emission de jeton signe avec `jti`, `scope` et `ttlSeconds`.
  - `POST /api/token/verify` : verification de signature, expiration (`exp`), revocation (`jti`) et `requiredScope`.
  - `POST /api/token/revoke` : revocation d un jeton par `jti` avec trace `TOKEN_REVOKE` dans l audit.

## Configuration (`.env`)

Copier `.env.example` puis renseigner les variables selon l environnement :

- `PORT` : port d ecoute HTTP (par defaut `3000`).
- `HIDE_OTP_IN_RESPONSE` : `true` pour masquer les codes OTP en production.
- `CONGOCONNECT_TOKEN_SECRET` : secret HMAC de signature/verification des jetons `cc1.`.
- `REDIS_URL` : URL Redis (repli automatique sur stockage memoire si non renseignee).
- `DATABASE_URL` : URL PostgreSQL pour la persistance d audit.

## Demarrage et tests

```powershell
node .\src\server.js
node --test .\test\smoke.test.js
```
