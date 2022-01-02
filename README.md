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

Configuring permissions in keycloak can be a little bit confusing check this link on stackoverflow [here](https://stackoverflow.com/questions/42186537/resources-scopes-permissions-and-policies-in-keycloak) where people try to explain how to do this.

Example: Restrict the `create` method of the `transactions` service in feathersjs to only users who have a `transactions:create` permission in keycloak.
```
import { hooks } from 'feathers-keycloak-connect-server'`

app.service('transactions').hooks({before: {create: hooks.hasPermission({resource: 'transactions', scopes: 'create'})}})
```
The `resource` and `scopes` fields when any is ommitted will pick from the feathers `service path` and `method` respectively.

This means that the above example can be achieved through

`app.service('transactions').hooks({before: {create: hooks.hasPermission()}})`


### hooks.getUser and hooks.getClient
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


# Client Side
## Install client library with `npm`:
  - `npm install --save feathers-keycloak-connect-client`

Note:
The client side code uses the `keycloak-js` behind the scence to login to keycloak and retrieve the `jwt`.

## Import and configure library with feathersjs client object
```
  import { AuthConfigure } from 'feathers-keycloak-connect-client';
  ... configure other libraries ...
  app.configure(AuthConfigure(KeycloakClientConfig));
```

`KeycloakClientConfig` is an object with the following fields:
* `keycloakConfig`: (required) this translate directly to the `KeycloakConfig` option needed by the `keycloak-js` library. you can check out the documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#_javascript_adapter).
* `keycloakInit`: (required) this translate directly to the `KeycloakInitOptions` option needed by the `keycloak-js` library. you can check out the documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#_javascript_adapter).
* `loginRedirectUri`: (optional defaults to '/') the uri to redirect to after a successful login.
* `logoutRedirectUri`: (optional defaults to '/') the uri to redirect to after a successful logout.
* `scope`: (optional) the scope to retrieve from the keycloak server when performing login action.
* `minValidity`: (optional defaults to 5secs) the minimum validity period before the `jwt` is refreshed.
* `withVueRouter`: (optional) this is a boolean value which determines if you are using the library with vue-router or not (defaults to `false` which means you are using without vue-router).
* `vueRouterLink`: (optional) this is needed if the `withVueRouter` option is true but defaults to (`/auth`). This is the path on vue-router where the `vue-router` component of this library has to be mounted. More details discussed later.

At the time of writing this documentation the required fields in the `KeycloakConfig` object are below. check official docs for any possible update or changes [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#_javascript_adapter):
* `url`: the url to the keycloak server (e.g. 'http://localhost:9000/auth').
* `realm`: the keycloak realm to use.
* `clientId`: the id of the configured client in keycloak.



At the time of writing this documentation the `KeycloakInitOptions` has no required fields (only optional fields) check official docs for any possible update or changes [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#_javascript_adapter) relevant fields include:
* `onLoad`: action to perform after the library is loaded. options are 
    `login-required` => checks if user is logged in and redirects to login page if not. Use this option if you want your users to be authenticated before reaching the home page of the app.
    `check-sso` => silently checks sso and loads user information if user is already logged in or nothing otherwise.

* `enableLogging`: boolean value to enable showing of logs in the browser console. Enable this only for debuging purposes.

Other options like `adapter`, `checkLoginIframe`, `flow` are also available. Check [docs](https://www.keycloak.org/docs/latest/securing_apps/index.html#_javascript_adapter) for more details.

### Full Configuration example

```
import feathers from '@feathersjs/feathers';
import socketio from '@feathersjs/socketio-client';
import io from 'socket.io-client';
import { AuthConfigure } from 'feathers-keycloak-connect-client'

const socket = io('http://localhost:3030');
const app = feathers();

app.configure(socketio(socket));
app.configure(AuthConfigure(KeycloakClientConfig));

app.on('authSuccess', (payload: any) => {
  console.log('login-info', payload);
})

```

replace the `socket.io-client` with any other client you want and the steps should be the same. However library has been extensively tested with the socket.io client and guaranteed to work. report any problem you find with other clients.


## Using library with vue-router.
Due to the nature and design of the vue-router library, you need to perform additional configuration in order to use this library with vue-router. 

The library needs to perform feather processing after redirection from login and the redirection route has to be mounted to the library. this can be done as below.

```
const app = ... // feathersjs client already configured with the library
const router = ... // configured vue-router object

app.authentication.configureVueRouter(router);
```

## Added properties or attributes
The following properties or attributes are available on the feathers client object after configuration:

### authentication
The authentication library itself is accessible through this property.

### keycloak
The keycloak object from `keycloak-js` library is also available here.

## Added functions or methods
The following functions or methods are available on the feathers client object after configuration:

### authenticated
 A function which returns `true` if user has logged in or false otherwise.

### authenticate | login
 A function which can be used to trigger the login action. That's redirect user to keycloak for authentication. Parameters are:
 * `redirectUri`: (optional) a redirect URI to override the defualt configured uri.
 * `params`: (optional) this is any parameters that should be sent to the `authSuccess` event listener after a successful login. This can be used to transfer data between pre and post login session.
 * `options`: (optional) this is an object containing any additional information passed to the `login` function of the `keycloak-js` object.

 ### reAuthenticate (async)
 This is used to manually trigger updating of the existing user token. Token updating is done automatically by the `keycloak-js` library and you might not need to call this function directly.

 ### logout
 Use this to logout current user. The takes an optional `redirectUri` parameter. Redirect to default uri provided during configuration if not provided here.

 ### accountManagement
 A wrapper around the `accountManagement` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference).

 ### register
 A wrapper around the `register` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference). It takes the user to the registration page of keycloak where the user can signup for a new account.

 ### hasRealmRole
 A wrapper around the `hasRealmRole` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference). Use this to check if the current user has a specific realm role in keycloak.

 ### hasResourceRole
 A wrapper around the `hasResourceRole` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference). Use this to check if the current user has a specific resource role.

 ### loadUserInfo
 A wrapper around the `loadUserInfo` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference).

 ### loadUserProfile
 A wrapper around the `loadUserProfile` function provided by the `keycloak-js` object. check documentation [here](https://www.keycloak.org/docs/latest/securing_apps/index.html#javascript-adapter-reference).

 ### hasPermission
 This is similar to the server side hook `hasPermissions`. Since most client side apps are configured as `public` clients in keycloak they do not have access to the `permissions`. The library circumvents this by returning the permissions from the feathersjs server. This function can then be used to check if the user has a specific permission on the feathersjs server.

 Example: to check if the current user has create permission on the transactions service.
 ```
  app.hasPermission({resource: 'transactions', scopes: 'create'})
 ```

 Returns `true` if user has permission, otherwise returns `false`.

 ## Added events
 the following events will triggered by the feathers client object after configureation.

 ### authSuccess
 Will be triggered on successful authentication.
 ```
 app.on('authSuccess', (payload) => {
   console.log(payload);
 })
 ```

 the `payload` object has the following fields:
 * `user`: the current user object.
 * `params`: the optional params object passed to the `login` function.

 ### authLogout
 Will be triggered on a successful logout.

 ### authError
 Will be triggered if there is an error during login.
 ```
 app.on('authError', (payload) => {
   console.log(payload);
 })
 ```

 the `payload` object has the following fields:
 * `error`: the error oject.
 * `params`: the optional params object passed to the `login` function.