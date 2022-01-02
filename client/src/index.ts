import Keycloak from 'keycloak-js';
import { Application } from '@feathersjs/feathers';

export interface KeycloakClientConfig {
  keycloakConfig: Keycloak.KeycloakConfig;
  keycloakInit: Keycloak.KeycloakInitOptions;
  loginRedirectUri?: string;
  logoutRedirectUri?: string;
  minValidity?: number;
  withVueRouter?: boolean;
  vueRouterLink?: string;
  scope?: string;
}

interface VueRouterComponent {
  render: any,
  method: any,
}

export class KeycloakClient {
  keycloak: Keycloak.KeycloakInstance;
  private app: any;
  private loginRedirectUri: string;
  private logoutRedirectUri: string;
  private minValidity: number;
  private currentUser!: any;
  private withVueRouter: boolean;
  private vueRouterLink: string;
  private scope: string;

  constructor(app: Application, config: KeycloakClientConfig) {
    this.app = app;
    this.keycloak = Keycloak(config.keycloakConfig);
    this.loginRedirectUri = config.loginRedirectUri || '/';
    this.logoutRedirectUri = config.logoutRedirectUri || '/';
    this.minValidity = config.minValidity || 5;
    this.scope = config.scope || '';

    this.keycloak.onAuthSuccess = () => { this.onAuthSuccess(); };
    this.keycloak.onTokenExpired = () => { this.onTokenExpired(); };
    this.keycloak.onAuthError = () => { this.onAuthError(); };
    this.keycloak.onAuthLogout = () => { this.onAuthLogout(); };

    this.withVueRouter = config.withVueRouter || false;
    this.vueRouterLink = config.vueRouterLink || '/auth';

    this.keycloak.init(config.keycloakInit);

    const socket = app.io || app.primus;
    if (socket) this.handleSocket(socket);
  }

  async onAuthSuccess(): Promise<void> {
    const token = this.keycloak.token;
    try {
      const user: any = await this.app.service('auth').create({ access_token: token });
      this.currentUser = user;
      let params: any = window.sessionStorage.getItem('keycloak-loginParams');
      if (params) {
        params = JSON.parse(params)
        params = params.params || null;
      } else {
        params = null;
      }
      this.app.emit('authSuccess', {user: this.currentUser, params});
    } catch (error) {
      this.currentUser = null;
    }
  }

  get user() {
    return this.currentUser;
  }

  private checkPermission(data: any[], resources: string|string[], scopes?: string|string[]): boolean {
    const res: string[] = Array.isArray(resources) ? resources : [resources];
    let scp: any = null;
    if (scopes) {
      scp = Array.isArray(scopes) ? scopes : [scopes]
    }
    for (let r = 0; r < res.length; r++) {
      const resData = data.filter((d: any) => d.rsname && d.rsname.toString() === res[r].toString())[0];
      if (resData) {
        if (!scp) return true;
        const resScopes: any = (resData.scopes || []).map((s: any) => s.toString());
        for (let s = 0; s < scp.length; s++) {
          if (resScopes.includes(scp[s].toString()) || scp[s] === '*') return true;
        }
      }
    }
    return false;
  }
  
  private resolvePermission(permission: any): any {
    if (typeof permission === 'string') {
      const opt = permission.split(':')
      return {resource: opt[0], scope: opt[1] || null};
    }
  
    if (permission.resource) {
      return permission;
    }
  }
  
  hasPermission (options?: any): boolean {
    const data: any[] = this.currentUser.permissions || [];
    const permissions: any[] = [];
    if (!options) {
      return true;
    } else {
      if (Array.isArray(options)) {
        for (let i = 0; i < options.length; i++) permissions.push(this.resolvePermission(options[i]));
      } else {
        permissions.push(this.resolvePermission(options));
      }
    }

    if (permissions.length > 0) {
      let res = false;
      for (let i = 0; i < permissions.length; i++) {
        res = res || this.checkPermission(data, permissions[i].resource, permissions[i].scope)
        if (res) return true;
      }
      if (!res) return false;
    }

    return true;
  }

  async onAuthLogout(): Promise<void> {
    this.currentUser = null;
    this.app.emit('authLogout');
  }

  handleSocket (socket: any): void {
    const connected = this.app.io ? 'connect' : 'open';
    const disconnected = this.app.io ? 'disconnect' : 'disconnection';
    socket.on(disconnected, () => {
      socket.once(connected, (data: any) => {
        this.reAuthenticate();
      });
    });
  }

  async onTokenExpired(): Promise<void> {
    await this.keycloak.updateToken(this.minValidity);
  }

  async getToken(): Promise<string|undefined> {
    const isExpired = this.keycloak.isTokenExpired();
    if (isExpired) await this.keycloak.updateToken(this.minValidity);
    return this.keycloak.token;
  }

  onAuthError(): void {
    let params: any = window.sessionStorage.getItem('keycloak-loginParams');
    if (params) {
      params = JSON.parse(params)
      params = params.params || null;
    } else {
      params = null;
    }
    this.app.emit('authError', {error: new Error('Unable to authenticate user!'), params});
  }

  login(redirectUri?: string, params?: any, options?: any): void {
    if (!this.keycloak.authenticated) {
      window.sessionStorage.setItem('keycloak-loginParams', JSON.stringify({params}));
      if (this.withVueRouter && this.vueRouterLink) {
        const ruri: string = this.makeURL(this.vueRouterLink);
        window.sessionStorage.setItem('keycloak-currentRedirect', redirectUri || this.loginRedirectUri);
        this.keycloak.login({ scope: this.scope, ...(options || {}), redirectUri: ruri });
      } else {
        const ruri: string = this.makeURL(redirectUri || this.loginRedirectUri);
        this.keycloak.login({ redirectUri: ruri });
      }
    } else {
      window.sessionStorage.setItem('keycloak-loginParams', JSON.stringify({params}));
      this.onAuthSuccess();
    }
  }

  vueRouterComponent(timeout?: number): VueRouterComponent {
    const component: any = {
      render: (h: any) => h('div'),
      mounted() {
        const ruri: string|null = window.sessionStorage.getItem('keycloak-currentRedirect');
        if (ruri) {
          setTimeout(() => {
            (this as any).$router.replace(ruri);
          }, timeout || 1000);
        }
      }
    }
    return component;
  }

  configureVueRouter(router: any, timeout?: number): void {
    router.addRoute({path: this.vueRouterLink, name: 'Keycloak-Authentication', component: this.vueRouterComponent(timeout)});
  }

  makeURL(path: string, origin?: string):string {
    if (path.includes('://')) {
      return path;
    } else if (origin) {
      return `${origin}${path.startsWith('/') ? '' : '/'}${path}`;
    } else {
      const orig = location.origin;
      return `${orig}${path.startsWith('/') ? '' : '/'}${path}`;
    }
  }

  async reAuthenticate(): Promise<void> {
    if (this.keycloak.token) await this.keycloak.updateToken(this.minValidity);
  }

  logout(redirectUri?: string): void {
    const ruri = this.makeURL(redirectUri || this.logoutRedirectUri);
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
    hasRealmRole: Keycloak.KeycloakInstance['hasRealmRole'];
    hasResourceRole: Keycloak.KeycloakInstance['hasResourceRole'];
    loadUserInfo: Keycloak.KeycloakInstance['loadUserInfo'];
    loadUserProfile: Keycloak.KeycloakInstance['loadUserProfile'];
    hasPermission: KeycloakClient['hasPermission'];
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
    app.hasRealmRole = keycloak.keycloak.hasRealmRole.bind(keycloak.keycloak);
    app.hasResourceRole = keycloak.keycloak.hasResourceRole.bind(keycloak.keycloak);
    app.loadUserInfo = keycloak.keycloak.loadUserInfo.bind(keycloak.keycloak);
    app.loadUserProfile = keycloak.keycloak.loadUserProfile.bind(keycloak.keycloak);
    app.register = keycloak.keycloak.register.bind(keycloak.keycloak);
    app.authenticated = keycloak.authenticated.bind(keycloak);
    app.hasPermission = keycloak.hasPermission.bind(keycloak)
    app.hooks({
      before: [keycloak.hook.bind(keycloak)]
    })
  }
};