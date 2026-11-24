# CongoConnect — Prototype Local (Node.js)

Prototype local de plateforme d authentification par OTP, de verification d identite simulee, d emission/verification de jetons signes (`cc1.*`), d annuaire de fournisseurs et de journalisation d audit.

## Structure du projet
- `.env.example` : variables d environnement
- `.gitignore` : exclusions Git (`node_modules/`, `logs/`, `.env`)
- `public/index.html` : interface web locale (`/app`)
- `src/server.js` : serveur HTTP et routage API
- `src/config/env.js` : configuration et modes de stockage
- `src/services/` : `otpService.js`, `identityProviderSim.js`, `pkiService.js`, `serviceProviderRegistry.js`, `auditLogService.js`
- `src/storage/auditStore.js` : persistance memoire + fichier `logs/audit.log`
- `test/smoke.test.js` : tests automatises (`node --test`)

## Demarrage rapide
1. Lancer le serveur : `node .\src\server.js`
2. Ouvrir l interface : `http://localhost:3000/app`
3. Lancer les tests (2e fenetre) : `node --test .\test\smoke.test.js`

## Routes principales
- `GET /` et `GET /health`
- `GET /app`
- `POST /api/otp/request` et `POST /api/otp/verify`
- `POST /api/identity/lookup`
- `GET /api/providers`
- `POST /api/token/issue` et `POST /api/token/verify`
- `GET /api/audit`
