# vault-ai-auth-server
hackwhat?

## Run locally

Requirements: Java 21 and access to the Oracle database.

1. Create a `.env` file in the project root (it is not committed):

   ```
   DB_URL=jdbc:oracle:thin:@<host>:<port>/<service>
   VAULT_AUTH_DB_PASSWORD=<password>
   OAUTH2_CLIENT_SECRET=<same value as in vault-ai-be>
   INTERNAL_API_KEY=<same value as in vault-ai-be>
   ```

   The schema user defaults to `VAULT_AUTH`; set `VAULT_AUTH_DB_USER` to override it.

2. Start the application with the `local` profile, from the project root:

   ```
   ./mvnw spring-boot:run -Dspring-boot.run.profiles=local
   ```

   On Windows PowerShell: `.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"`

3. Check that it is up: http://localhost:9000/actuator/health

On the `local` profile:

- Liquibase creates or updates the tables at startup.
- A verified test user is created from `app.test-user` in `application-local.yml`.
- Emails are not sent. They are written to the log with the prefix `[MAIL NOT SENT]`; copy the verification or reset link from there.
- The token signing key is generated at startup, so users are signed out after a restart.

Start this application before `vault-ai-be`.