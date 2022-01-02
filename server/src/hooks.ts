import { Forbidden } from '@feathersjs/errors';

export function getUser(context: any) {
  if (context?.params?.provider === 'socketio' && context?.params.connection) {
    return context.params.connection.user || null;
  } else if (!context.params.provider) {
    return {isInternal: true}
  } else {
    return context?.params?.user || null;
  }
}

export function getClient(context: any) {
  if (context?.params?.provider === 'socketio' && context?.params.connection) {
    return context.params.connection.client || null;
  } else if (!context.params.provider) {
    return {isInternal: true};
  } else {
    return context?.params?.client || null;
  }
}

export const protect = function (options?: any): any {
  return async function(context: any) {
    if (!context.params.provider) return context;
    const user = getUser(context);
    const client = getClient(context);
    if (user && client) return context;
    throw new Forbidden('Access Denied!');
  }
};

export interface ResrictToOwnerOptions {
  idField?: string,
  ownerField?: string,
}

function getField(obj: any, field: string): any {
  return field.split('.').reduce((c: any, r: any) => { return c ? c[r] : c }, obj);
}

export const restrictToOwner = function (options?: ResrictToOwnerOptions): any {
  let opts = {...{ idField: 'profile._id', ownerField: '_id' }, ...options || {}};
  return async function(context: any) {
    let user = getUser(context);
    if (user && user.isInternal) return context
    if (user) {
      let userId = getField(user, opts.idField);
      if (!context.params.query) context.params.query = {};
      context.params.query[opts.ownerField] = userId;
      return context;
    }
    throw new Forbidden('Access Denied!');
  }
};

export interface AccessOptions {
  resource: string | string[];
  role: string | string[]
}

export const hasResourceRole = function (options?: AccessOptions | AccessOptions[]): any {
  return async function(context: any) {
    const user = getUser(context);
    const client = getClient(context);
    if (user && user.isInternal) return context
    if (user && client) {
      const res: any = client.resource_access || {};
      let hasAccess = false;
      if (Array.isArray(options)) {
        for (let o = 0; o < options.length; o++) {
          hasAccess = hasAccess || checkResourceAccess(res, options[o].resource || [context.path], options[o].role || [context.method]);
        }
      } else {
        hasAccess = checkResourceAccess(res, options?.resource || [context.path], options?.role || [context.method]);
      }
      if (!hasAccess) {
        throw new Forbidden('Access Denied!');
      } else {
        return context;
      }
    }
    throw new Forbidden('Access Denied!');
  }
};

function checkResourceAccess(data: any, resources: string|string[], roles: string|string[]): boolean {
  let res: any = resources;
  let ros: any = roles;

  if (!Array.isArray(res)) res = [res];
  if (!Array.isArray(ros)) ros = [ros];

  let r: any = [];
  for (const k of Object.keys(data)) {
    if (res.includes(k) || res.includes('*')) {
      r = r.concat(data[k].roles || []);
    }
  }
  for (let i = 0; i < ros.length; i++) {
    if (r.includes(ros[i])) return true;
  }
  return false;
}

export const hasRealmRole = function (options: string|string[]): any {
  return async function(context: any) {
    const user = getUser(context);
    const client = getClient(context);
    if (user && user.isInternal) return context
    if (user && client) {
      let hasAccess = false;
      const roles: any = client.realm_access?.roles || [];
      if (Array.isArray(options)) {
        for (let o = 0; o < options.length; o++) {
          hasAccess = hasAccess || roles.includes(options[o]);
        }
      } else {
        hasAccess = roles.includes(options);
      }
      if (!hasAccess) {
        throw new Forbidden('Access Denied!');
      } else {
        return context;
      }
    }
    throw new Forbidden('Access Denied!');
  }
};

function checkPermission(data: any[], resources: string|string[], scopes?: string|string[]): boolean {
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

function resolvePermission(permission: any): any {
  if (typeof permission === 'string') {
    const opt = permission.split(':')
    return {resource: opt[0], scope: opt[1] || null};
  }

  if (permission.resource) {
    return permission;
  }
}

export const hasPermission = function (options?: any): any {
  return async function(context: any) {
    const data: any[] = context.params.permissions;
    const permissions: any[] = [];
    if (!options) {
      permissions.push({resource: context.path, scope: context.method})
    } else {
      if (Array.isArray(options)) {
        for (let i = 0; i < options.length; i++) {
          permissions.push(resolvePermission(options[i]));
        }
      } else {
        permissions.push(resolvePermission(options));
      }
    }

    if (permissions.length > 0) {
      let res = false;
      for (let i = 0; i < permissions.length; i++) {
        res = res || checkPermission(data, permissions[i].resource, permissions[i].scope);
        if (res) return context;
      }
      if (!res) throw new Forbidden('Access Denied!');
    }
    return context;
  }
}