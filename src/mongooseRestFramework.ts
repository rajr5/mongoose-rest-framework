import bodyParser from "body-parser";
import express from "express";
import session from "express-session";
import jwt from "jsonwebtoken";
import mongoose, {Model, Schema} from "mongoose";
import passport from "passport";
import {Strategy as JwtStrategy, ExtractJwt} from "passport-jwt";

// TODOS:
// Firebase auth
// Support bulk actions
// Support more complex query fields

type RESTMethod = "list" | "create" | "read" | "update" | "delete";

interface GooseTransformer<T> {
  // Runs before create or update operations. Allows throwing out fields that the user should be
  // able to write to, modify data, check permissions, etc.
  transform?: (obj: Partial<T>, method: "create" | "update", user?: User) => Partial<T> | undefined;
  // Runs after create/update operations but before data is returned from the API. Serialize fetched
  // data, dropping fields based on user, changing data, etc.
  serialize?: (obj: T, user?: User) => Partial<T> | undefined;
}

type UserType = "anon" | "auth" | "owner" | "admin";

interface User {
  id: string;
  admin: boolean;
  isAnonymous?: boolean;
}

type PermissionMethod<T> = (method: RESTMethod, user?: User, obj?: T) => boolean;

interface RESTPermissions<T> {
  create: PermissionMethod<T>[];
  list: PermissionMethod<T>[];
  read: PermissionMethod<T>[];
  update: PermissionMethod<T>[];
  delete: PermissionMethod<T>[];
}

interface GooseRESTOptions<T> {
  permissions: RESTPermissions<T>;
  queryFields?: string[];
  queryFilter?: (user?: User) => Record<string, any> | undefined;
  transformer?: GooseTransformer<T>;
}

export const Permissions = {
  IsAuthenticatedOrReadOnly: (method: RESTMethod, user?: User) => {
    if (user?.id && !user?.isAnonymous) {
      return true;
    }
    if (method === "list" || method === "read") {
      return true;
    }
    return false;
  },
  IsOwnerOrReadOnly: (method: RESTMethod, user?: User, obj?: any) => {
    // When checking if we can possibly perform the action, return true.
    if (!obj) {
      return true;
    }
    if (user?.admin) {
      return true;
    }

    if (user?.id && obj?.ownerId && String(obj?.ownerId) === String(user?.id)) {
      return true;
    }
    if (method === "list" || method === "read") {
      return true;
    }
    return false;
  },
  IsAny: () => {
    return true;
  },
  IsOwner: (method: RESTMethod, user?: User, obj?: any) => {
    // When checking if we can possibly perform the action, return true.
    if (!obj) {
      return true;
    }
    if (!user) {
      return false;
    }
    if (user?.admin) {
      return true;
    }
    return user?.id && obj?.ownerId && String(obj?.ownerId) === String(user?.id);
  },
  IsAdmin: (method: RESTMethod, user?: User) => {
    return Boolean(user?.admin);
  },
  IsAuthenticated: (method: RESTMethod, user?: User) => {
    if (!user) {
      return false;
    }
    return Boolean(user.id);
  },
};

// Defaults closed
function checkPermissions<T>(
  method: RESTMethod,
  permissions: PermissionMethod<T>[],
  user?: User,
  obj?: T
): boolean {
  let anyTrue = false;
  for (const perm of permissions) {
    if (perm(method, user, obj) === false) {
      return false;
    } else {
      anyTrue = true;
    }
  }
  return anyTrue;
}

export function tokenPlugin(schema: Schema) {
  schema.add({token: {type: String, index: true}});
  schema.pre("save", function(next) {
    // Add created when creating the object
    if (!this.token) {
      this.token = jwt.sign(this._id, (process.env as any).TOKEN_SECRET, {expiresIn: "1800s"});
    }
    // On any save, update updated.
    this.updated = new Date();
    next();
  });
}

export function firebaseJWTPlugin(schema: Schema) {
  schema.add({firebaseId: {type: String, index: true}});
}

// TODO allow customization
export function setupAuth(
  app: express.Application,
  options: {
    disableBasicAuth?: boolean;
    sessionSecret: string;
    jwtSecret?: string;
    jwtIssuer?: string;
  }
) {
  const UserModel = mongoose.model("User") as any;
  if (!options.disableBasicAuth) {
    passport.use(UserModel.createStrategy());
  }
  // use static serialize and deserialize of model for passport session support
  passport.serializeUser(UserModel.serializeUser());
  passport.deserializeUser(UserModel.deserializeUser());

  if (options.jwtSecret && options.jwtIssuer) {
    const jwtOpts = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: options.jwtSecret,
      issuer: options.jwtIssuer,
      audience: "mongooseRestFramework",
    };
    passport.use(
      new JwtStrategy(jwtOpts, async function(jwtPayload: any, done: any) {
        let user;
        try {
          user = UserModel.findOne({firebaseId: jwtPayload.sub});
        } catch (e) {
          return done(e, false);
        }
        if (user) {
          return done(null, user);
        } else {
          return done(null, false);
          // or you could create a new account
        }
      })
    );
  }

  const router = express.Router();
  router.post("/login", passport.authenticate("local", {}), function(req: any, res: any) {
    res.json({data: req.user});
  });

  app.use(session({secret: options.sessionSecret}) as any);
  app.use(bodyParser.urlencoded({extended: false}) as any);
  app.use(passport.initialize() as any);
  app.use(passport.session());

  app.use("/auth", router);
}

function getUserType(user?: User, obj?: any): UserType {
  if (user?.admin) {
    return "admin";
  }
  if (obj && user && String(obj?.ownerId) === String(user?.id)) {
    return "owner";
  }
  if (user?.id) {
    return "auth";
  }
  return "anon";
}

export function AdminOwnerTransformer<T>(options: {
  // TODO: do something with KeyOf here.
  anonReadFields?: string[];
  authReadFields?: string[];
  ownerReadFields?: string[];
  adminReadFields?: string[];
  anonWriteFields?: string[];
  authWriteFields?: string[];
  ownerWriteFields?: string[];
  adminWriteFields?: string[];
}): GooseTransformer<T> {
  function pickFields(obj: Partial<T>, fields: any[]): Partial<T> {
    const newData: Partial<T> = {};
    for (const field of fields) {
      if (obj[field] !== undefined) {
        newData[field] = obj[field];
      }
    }
    return newData;
  }

  return {
    transform: (obj: Partial<T>, method: "create" | "update", user?: User) => {
      const userType = getUserType(user, obj);
      let allowedFields: any;
      if (userType === "admin") {
        allowedFields = options.adminWriteFields ?? [];
      } else if (userType === "owner") {
        allowedFields = options.ownerWriteFields ?? [];
      } else if (userType === "auth") {
        allowedFields = options.authWriteFields ?? [];
      } else {
        allowedFields = options.anonWriteFields ?? [];
      }
      const unallowedFields = Object.keys(obj).filter((k) => !allowedFields.includes(k));
      if (unallowedFields.length) {
        throw new Error(
          `User of type ${userType} cannot write fields: ${unallowedFields.join(", ")}`
        );
      }
      return obj;
    },
    serialize: (obj: T, user?: User) => {
      const userType = getUserType(user, obj);
      if (userType === "admin") {
        return pickFields(obj, [...(options.adminReadFields ?? []), "id"]);
      } else if (userType === "owner") {
        return pickFields(obj, [...(options.ownerReadFields ?? []), "id"]);
      } else if (userType === "auth") {
        return pickFields(obj, [...(options.authReadFields ?? []), "id"]);
      } else {
        return pickFields(obj, [...(options.anonReadFields ?? []), "id"]);
      }
    },
  };
}

export function gooseRestRouter<T>(
  model: Model<any>,
  options: GooseRESTOptions<T>
): express.Router {
  const router = express.Router();

  function transform(data: Partial<T> | Partial<T>[], method: "create" | "update", user?: User) {
    if (!options.transformer?.transform) {
      return data;
    }

    // TS doesn't realize this is defined otherwise...
    const transformFn = options.transformer?.transform;

    if (!Array.isArray(data)) {
      return transformFn(data, method, user);
    } else {
      return data.map((d) => transformFn(d, method, user));
    }
  }

  function serialize(data: T | T[], user?: User) {
    if (!options.transformer?.serialize) {
      return data;
    }

    // TS doesn't realize this is defined otherwise...
    const serializeFn = options.transformer?.serialize;

    if (!Array.isArray(data)) {
      return serializeFn(data, user);
    } else {
      return data.map((d) => serializeFn(d, user));
    }
  }

  router.post("/", async (req, res) => {
    if (!checkPermissions("create", options.permissions.create, req.user)) {
      return res.status(405).send();
    }

    let body;
    try {
      body = transform(req.body, "create", req.user);
    } catch (e) {
      return res.status(403).send({message: (e as any).message});
    }
    const data = await model.create(body);
    return res.json({data: serialize(data, req.user)});
  });

  router.get("/", async (req, res) => {
    if (!checkPermissions("list", options.permissions.list, req.user)) {
      return res.status(403).send();
    }

    let query = {};

    for (const queryParam of Object.keys(req.query)) {
      if ((options.queryFields ?? []).includes(queryParam)) {
        query[queryParam] = req.query[queryParam];
      }
    }

    if (options.queryFilter) {
      query = {...query, ...options.queryFilter(req.user)};
    }

    // TODO add query
    const data = await model.find(query);
    // TODO add pagination
    return res.json({data: serialize(data, req.user)});
  });

  router.get("/:id", async (req, res) => {
    if (!checkPermissions("read", options.permissions.read, req.user)) {
      return res.status(405).send();
    }

    const data = await model.findById(req.params.id);

    if (!data) {
      return res.status(404).send();
    }

    if (!checkPermissions("read", options.permissions.read, req.user, data)) {
      return res.status(403).send();
    }

    return res.json({data: serialize(data, req.user)});
  });

  router.put("/:id", async (req, res) => {
    // Patch is what we want 90% of the time
    return res.status(500);
  });

  router.patch("/:id", async (req, res) => {
    if (!checkPermissions("update", options.permissions.update, req.user)) {
      return res.status(405).send();
    }

    let doc = await model.findById(req.params.id);

    if (!doc) {
      return res.status(404).send();
    }

    if (!checkPermissions("update", options.permissions.update, req.user, doc)) {
      return res.status(403).send();
    }

    let body;
    try {
      body = transform(req.body, "update", req.user);
    } catch (e) {
      return res.status(403).send({message: (e as any).message});
    }
    doc = await model.findOneAndUpdate({_id: req.params.id}, body, {new: true});
    return res.json({data: serialize(doc, req.user)});
  });

  router.delete("/:id", async (req, res) => {
    if (!checkPermissions("delete", options.permissions.delete, req.user)) {
      return res.status(405).send();
    }

    const data = await model.findById(req.params.id);

    if (!data) {
      return res.status(404).send();
    }

    if (!checkPermissions("delete", options.permissions.delete, req.user, data)) {
      return res.status(403).send();
    }

    return res.json({data: serialize(data, req.user)});
  });

  return router;
}
