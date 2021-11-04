import axios from 'axios';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { Forbidden } from '@feathersjs/errors';
import * as authHooks from './hooks';

export const hooks = authHooks;

export interface KeycloakServerConfig {
  serverUrl: string,
  realm: string,
  clientId: string,
  secret?: string,
  userService?: string,
  serviceIdField?: string
}

export class KeycloakServer {
  config: KeycloakServerConfig;
  endpoints: any;
  keystore: any;

  constructor(config: KeycloakServerConfig) {
    this.config = config;
    this.endpoints = {
      certs: '/realms/{realm-name}/protocol/openid-connect/certs'
    };
    this.keystore = createRemoteJWKSet(new URL(`${this.config.serverUrl}${this.resolveURL(this.endpoints.certs)}`));
  }

  async post(url: string, data: any): Promise<any> {
    let formData: FormData = new FormData();
    formData.set('client_id', this.config.clientId);
    if (this.config.secret) formData.set('client_secret', this.config.secret);
    for (let k of Object.keys(data)) {
      formData.set(k, data[k]);
    }
    return axios.post(`${this.config.serverUrl}${url}`, formData)
  }

  resolveURL(url: string): string {
    let realm: string = this.config.realm;
    let rUrl: string = url.replace('{realm-name}', realm);
    return rUrl;
  }
  
  async verifyToken(token: string): Promise<any> {
    let response: any = null;
    try {
      const { payload }: any = await jwtVerify(token, this.keystore);
      response = {}
      response.user = {
        email: payload.email,
        verified: payload.email_verified,
        username: payload.preferred_username,
        firstName: payload.given_name,
        lastName: payload.family_name,
        _id: payload.sub,
        id: payload.sub,
      };
      response.client = {
        _id: payload.azp,
        id: payload.azp,
        realm_access: payload.realm_access,
        resource_access: payload.resource_access,
        allowed_origins: payload['allowed-origins'],
        scope: payload.scope,
        audience: payload.aud,
      };
    } catch (error) {
    }
    return response;
  }

  middleware (app: any) {
    return async (req: any, res: any, next: any) => {
      if (req && req.headers && req.headers.authorization && req.headers.authorization.toLowerCase().includes('bearer')) {
        const token: any = req.headers.authorization.split(' ')[1]
        if (token) {
          const content = await this.verifyToken(token);
          if (content) {
            if (content.user && content.user._id) {
              const profileQuery: any = {};
              profileQuery[this.config.serviceIdField || 'keycloakId'] = content.user._id;
              const service: any = app.service(this.config.userService || 'users')
              if (service) {
                const profile: any = await service.find({query: {...profileQuery, $limit: 1}});
                if (profile.data?.length > 0) {
                  content.user.profile = profile.data[0];
                } else {
                  const newProfile: any = await service.create(profileQuery)
                  content.user.profile = newProfile;
                }
              } else {
                content.user.profile = {};
              }
            }
            req.feathers.user = content.user;
            req.feathers.client = content.client;
          }
        }
      }
      next();
    }
  }

  authHook () {
    return async (context: any) => {
      const token: any = context.data && context.data.access_token ? context.data.access_token : null;
      if (token) {
        const content: any = await this.verifyToken(token);
        if (content) {
          context.params.$token = content;
          if (context.params.provider === 'socketio' && context.params.connection) {
            if (content.user && content.user._id) {
              const profileQuery: any = {};
              profileQuery[this.config.serviceIdField || 'keycloakId'] = content.user._id;
              const service: any = context.app.service(this.config.userService || 'users');
              if (service) {
                const profile: any = await service.find({query: {...profileQuery, $limit: 1}});
                if (profile.data?.length > 0) {
                  content.user.profile = profile.data[0];
                } else {
                  const newProfile: any = await service.create(profileQuery)
                  content.user.profile = newProfile;
                }
              } else {
                content.user.profile = {};
              }
            }
            context.params.connection.user = content.user;
            context.params.connection.client = content.client;
          }
        }
      }
      return context;
    }
  }

  authService (app: any) {
    const methods: any = {};
    methods.create = async (data: any, params: any) => {
      const content: any = params && params.$token;
      if (content) {
        app.emit('login', data, params, {});
        return content.user;
      } else {
        throw new Forbidden('access token error!');
      }
    };

    methods.remove = async (id: any, params: any) => {
      const connection: any = params.connection || {};
      app.emit('logout', id, params, {});
      return connection.user || {};
    }
    
    return methods
  }
}

export const AuthConfigure = function (config: KeycloakServerConfig) {
  return (app: any) => {
    const keycloak: KeycloakServer = new KeycloakServer(config);
    app.use(keycloak.middleware(app));
    app.use('/auth', keycloak.authService(app));
    app.service('/auth').hooks({
      before: {
        create: [keycloak.authHook()]
      }
    });
    app.set('keycloak', keycloak);
  }
};