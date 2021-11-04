import Keycloak from 'keycloak-js';
import { Application } from '@feathersjs/feathers';

export interface KeycloakClientConfig {
  keycloakConfig: Keycloak.KeycloakConfig,
  keycloakInit: Keycloak.KeycloakInitOptions,
  loginRedirectUri?: string,
  logoutRedirectUri?: string,
  minValidity?: number
}

export class KeycloakClient {
  keycloak: Keycloak.KeycloakInstance;
  private app: any;
  private loginRedirectUri: string;
  private logoutRedirectUri: string;
  private minValidity: number;
  
  onLoginSuccess!: any;
  onLogoutSuccess!: any;
  onLoginError!: any;

  constructor(app: Application, config: KeycloakClientConfig) {
    this.app = app;
    this.keycloak = Keycloak(config.keycloakConfig);
    this.loginRedirectUri = config.loginRedirectUri || location.href;
    this.logoutRedirectUri = config.logoutRedirectUri || location.href;
    this.minValidity = config.minValidity || 5;

    this.keycloak.onAuthSuccess = () => { this.onAuthSuccess(); };
    this.keycloak.onTokenExpired = () => { this.onTokenExpired(); };
    this.keycloak.onAuthError = () => { this.onAuthError(); };
    this.keycloak.onAuthLogout = () => { this.onAuthLogout(); };

    this.keycloak.init(config.keycloakInit);

    const socket = app.io || app.primus;
    if (socket) this.handleSocket(socket);
  }

  async onAuthSuccess() {
    const token = this.keycloak.token
    const user: any = await this.app.service('auth').create({ access_token: token });
    if (this.onLoginSuccess && typeof this.onLoginSuccess === 'function') {
      this.onLoginSuccess(user);
    }
  }

  async onAuthLogout() {
    if (this.onLoginSuccess && typeof this.onLoginSuccess === 'function') {
      this.onLogoutSuccess();
    }
  }

  handleSocket (socket: any) {
    const connected = this.app.io ? 'connect' : 'open';
    const disconnected = this.app.io ? 'disconnect' : 'disconnection';
    socket.on(disconnected, () => {
      socket.once(connected, (data: any) => {
        this.reAuthenticate();
      });
    });
  }

  async onTokenExpired() {
    await this.keycloak.updateToken(this.minValidity);
  }

  async getToken(): Promise<string|undefined> {
    const isExpired = this.keycloak.isTokenExpired();
    if (isExpired) await this.keycloak.updateToken(this.minValidity);
    return this.keycloak.token;
  }

  onAuthError() {
    if (this.onLoginError && typeof this.onLoginError === 'function') {
      this.onLoginError(new Error('Unable to authenticate user!'));
    }
  }

  login(redirectUri?: string): void {
    const ruri = redirectUri || this.loginRedirectUri;
    if (!this.keycloak.authenticated) this.keycloak.login({ redirectUri: ruri });
  }

  async reAuthenticate(): Promise<void> {
    if (this.keycloak.token) await this.keycloak.updateToken(this.minValidity);
  }

  logout(redirectUri?: string): void {
    const ruri = redirectUri || this.logoutRedirectUri;
    this.keycloak.logout({ redirectUri: ruri });
  }

  authenticated(): boolean|undefined {
    return this.keycloak.authenticated;
  }

  async hook(context: any): Promise<any> {
    if (this.keycloak.authenticated) {
      const token = await this.getToken();
      if (token) {
        if (!context.params.headers) context.params.headers = {};
        context.params.headers['Authorization'] = `Bearer ${token}`;
      }
    }
    return context;
  }
}

declare module '@feathersjs/feathers' {
  interface Application<ServiceTypes = {}> {
    io?: any;
    rest?: any;
    primus?: any;
    authentication: KeycloakClient;
    keycloak: Keycloak.KeycloakInstance;
    authenticated: KeycloakClient['authenticated'];
    authenticate: KeycloakClient['login'];
    reAuthenticate: KeycloakClient['reAuthenticate'];
    login: KeycloakClient['login'];
    logout: KeycloakClient['logout'];
    accountManagement: Keycloak.KeycloakInstance['accountManagement'];
    register: Keycloak.KeycloakInstance['register'];
  }
}

export const AuthConfigure = function (config: KeycloakClientConfig) {
  return (app: Application) => {
    const keycloak: KeycloakClient = new KeycloakClient(app, config);
    app.authentication = keycloak;
    app.keycloak = keycloak.keycloak;
    app.authenticate = keycloak.login.bind(keycloak);
    app.login = keycloak.login.bind(keycloak);
    app.logout = keycloak.logout.bind(keycloak);
    app.reAuthenticate = keycloak.reAuthenticate.bind(keycloak);
    app.accountManagement = keycloak.keycloak.accountManagement.bind(keycloak.keycloak);
    app.register = keycloak.keycloak.register.bind(keycloak.keycloak);
    app.authenticated = keycloak.authenticated.bind(keycloak);
    app.hooks({
      before: [keycloak.hook.bind(keycloak)]
    })
  }
};