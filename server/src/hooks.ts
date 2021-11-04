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

export const restrictToOwner = function (options?: ResrictToOwnerOptions): any {
  let opts = {...{ idField: '_id', ownerField: '_id' }, ...options || {}};
  return async function(context: any) {
    let user = getUser(context);
    if (user && user.isInternal) return context
    if (user) {
      let userId = user[opts.idField];
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

export const resourceAccess = function (options?: AccessOptions | AccessOptions[]): any {
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

export const realmAccess = function (options: string|string[]): any {
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