# Featherjs Keycloak Connector

A Lightweight library to secure feathersjs API with keycloak authentication with both server and client support.

# Server Side

1. Install server library with `npm`:
  - `npm install --save feathers-keycloak-connect-server`

2. Import and configure library with feathersjs application object
  - `import { AuthConfigure } from 'feathers-keycloak-connect-server'`
  - `app.configure(AuthConfigure(keycloakServerOptions))`
  
