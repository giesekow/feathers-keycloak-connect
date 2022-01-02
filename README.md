# Featherjs Keycloak Connector

A Lightweight library to secure feathersjs API with keycloak authentication with both server and client support.

# Server Side

## Install server library with `npm`:
  - `npm install --save feathers-keycloak-connect-server`

## Import and configure library with feathersjs application object
```
  import { AuthConfigure } from 'feathers-keycloak-connect-server';
  app.configure(AuthConfigure(keycloakServerOptions));
```

`KeycloakServerOptions` is an object with the following fields:
  * `serverUrl`: string, the url to the keycloak server (e.g `http://localhost:9000/auth`)
  * `realm`: string, the keycloak realm
  * `clientId`: string, the clientId of the configured client in keycloak
  * `secret`: string (optional), the secret key of the configured client in keycloak (this is needed if you want to support permissions in feathersjs) the secret key is available for confidential clients.
  * `userService`: string (optional, default='users'), the user account service configured in feathers.
  * `serviceIdField`: string (optional, default='keycloakId') the id field in the userService where to retrieve user profile for the currently logged in user.

Once configured, the `params` object in feathers hooks and services will be patched with the `user`, `client`, and `permissions` object.
  * `user`: this contains information about the currently logged in user. if the `userService` and `serviceIdField` options are configured then the user information in feathersjs is attached to the `user` field as `profile`.
  * `client`: this contains information about which keycloak client was used to generate the `jwt` sent to feathersjs.
  * `permissions`: (optional) present if the `secret` field is provided in the `keycloakServerOptions`. contains a list of keycloak permissions available to the currently logged in user with respect to the client configured in keycloak for use by the feathersjs server.


## Hooks available
The library comes with hooks for performing security and access control.
You can get the `hooks` object as follows
  `import { hooks } from 'feathers-keycloak-connect-server'`

### hooks.protect
this hook checks if a user has logged in and if not will throw an access denied error!. This does not apply to internal server request where the `params.provider` field is `undefined` unless explicitly defined.

Example: To restrict the messages service to only logged in users.
```
import { hooks } from 'feathers-keycloak-connect-server';

app.service('messages').hooks({before: hooks.protect()});
```

### hooks.restrictToOwner
use this to restrict an operation to the owner of the object. e.g. will be to only allow users to update their own profile. The hook takes two fields in the `options` object:
* `idField`: where to find the id value in the `params.user` object defaults to `profile._id`.

* `ownerField`: where to find the id value in the restricting service object defaults to `_id`.

Example: To restrict patching of `comments` service by only the user who created it.
```
import { hooks } from 'feathers-keycloak-connect-server';

app.service('comments').hooks({before: {patch: hooks.restrictToOwner({ownerField: 'createdBy'})}});
```

### hooks.hasRealmRole
this checks if the current user has a specific role or roles in the keycloak realm.

takes a string which represent the role we want to check or a list of roles. In the case of a list the user is granted access if he has atleast one of the roles in the list.

Example: restricting user creation to only users with `admin` role in keycloak.
```
import { hooks } from 'feathers-keycloak-connect-server';

app.service('users').hooks({before: {create: hooks.hasRealmRole('admin')}});
```

### hooks.hasResourceRole
this is similar to the `hasRealmRole` hook. However this is checked against a specific resource and not the whole realm.
This takes the `ResourceAccessOptions` object or a list of `ResourceAccessOptions`.

The `ResourceAccessOptions` is an object with two required fields
* `resource`: the keycloak resource (e.g. 'account')
* `role`: the keycloak reource role (e.g. 'view-profile')

Where a list is provided, access is granted if the user has at least one of the requirements.

Example: Restrict the `find` method of the `users` services to only users with the `account:view-profile` resource-role.
```
import { hooks } from 'feathers-keycloak-connect-server';

app.service('users').hooks({before: {find: hooks.hasResourceRole({resource: 'account', role: 'view-profile'})}});
```

### hooks.hasPermission
This hook checks if the current users passes the stated permission or atleast one of the group of permissions. For permissions to work you need to provide the `secret` field when configuring the library in the ``.

Configuring permissions in keycloak can be a little bit confusing check this link on stackoverflow `https://stackoverflow.com/questions/42186537/resources-scopes-permissions-and-policies-in-keycloak` where people try to explain how to do this.

Example: Restrict the `create` method of the `transactions` service in feathersjs to only users who have a `transactions:create` permission in keycloak.
```
import { hooks } from 'feathers-keycloak-connect-server'`

app.service('transactions').hooks({before: {create: hooks.hasPermission({resource: 'transactions', scopes: 'create'})}})
```
The `resource` and `scopes` fields when any is ommitted will pick from the feathers `service path` and `method` respectively.

This means that the above example can be achieved through

`app.service('transactions').hooks({before: {create: hooks.hasPermission()}})`


### getUser and getClient
these are utility hooks to retrieve the current user and client from the `context` object in the service hook.

Example: getting the current user in your custom hook.
```
import { hooks } from 'feathers-keycloak-connect-server';

function (options): {
  return async function(context) {
    const user = hooks.getUser(context);
    const client = hooks.getClient(context);
  }
}
```