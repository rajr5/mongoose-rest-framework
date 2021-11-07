import bodyParser from "body-parser";
import express from "express";
import session from "express-session";
import jwt from "jsonwebtoken";
import mongoose, {Document, Model, Schema} from "mongoose";
import passport from "passport";
import {Strategy as FirebaseStrategy, ExtractJwt} from "passport-firebase-jwt";

// TODOS:
// Firebase auth
// Support bulk actions
// Support more complex query fields

const SPECIAL_QUERY_PARAMS = ["limit", "page"];

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

interface UserModel extends Model<User> {
  createStrategy(): any;
  serializeUser(): any;
  deserializeUser(): any;
  createAnonymousUser?: (id: string) => Promise<User>;
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
  sort?: string | {[key: string]: "ascending" | "descending"};
  defaultQueryParams?: {[key: string]: any};
  populatePaths?: string[];
  defaultLimit?: number; // defaults to 100
  maxLimit?: number; // defaults to 500
  endpoints?: (router: any) => void;
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
export function checkPermissions<T>(
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
  userModel: UserModel,
  options: {
    disableBasicAuth?: boolean;
    sessionSecret: string;
    jwtSecret?: string;
    jwtIssuer?: string;
  }
) {
  if (!userModel.createStrategy) {
    throw new Error("setupAuth userModel must have .createStrategy()");
  }
  if (!userModel.serializeUser) {
    throw new Error("setupAuth userModel must have .serializeUser()");
  }
  if (!userModel.deserializeUser) {
    throw new Error("setupAuth userModel must have .deserializeUser()");
  }

  if (!options.disableBasicAuth) {
    passport.use(userModel.createStrategy());
  }
  // use static serialize and deserialize of model for passport session support
  passport.serializeUser(userModel.serializeUser());
  passport.deserializeUser(userModel.deserializeUser());

  if (options.jwtSecret && options.jwtIssuer) {
    console.log("Setting up JWT Authentication");

    const jwtOpts = {
      jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("Bearer"),
    };
    passport.use(
      new FirebaseStrategy(jwtOpts, async function(jwtPayload: any, done: any) {
        let user;
        const payload = jwt.decode(jwtPayload);
        if (!payload) {
          return done(null, false);
        }
        try {
          user = await userModel.findOne({firebaseId: payload.sub});
        } catch (e) {
          return done(e, false);
        }
        if (user) {
          return done(null, user);
        } else {
          if (userModel.createAnonymousUser) {
            user = await userModel.createAnonymousUser(payload.sub as string);
            return done(null, user);
          } else {
            return done(null, false);
          }
        }
      })
    );
  }

  const router = express.Router();
  router.post("/login", passport.authenticate("local", {}), function(req: any, res: any) {
    res.json({data: req.user});
  });

  router.get("/me", passport.authenticate("firebase-jwt", {session: false}), async (req, res) => {
    if (!req.user?.id) {
      return res.status(401).send();
    }
    const data = await userModel.findById(req.user.id);

    if (!data) {
      return res.status(404).send();
    }
    (data as any).id = data._id;
    console.log("DATA ID", data.id);
    return res.json({data});
  });

  router.patch("/me", passport.authenticate("firebase-jwt", {session: false}), async (req, res) => {
    if (!req.user?.id) {
      return res.status(401).send();
    }
    // TODO support limited updates for profile.
    // try {
    //   body = transform(req.body, "update", req.user);
    // } catch (e) {
    //   return res.status(403).send({message: (e as any).message});
    // }
    try {
      const data = await userModel.findOneAndUpdate({_id: req.user.id}, req.body, {new: true});

      (data as any).id = data._id;
      return res.json({data});
    } catch (e) {
      return res.status(403).send({message: (e as any).message});
    }
  });

  app.use(session({secret: options.sessionSecret, resave: true, saveUninitialized: true}) as any);
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

  function serialize(data: Document<T, {}, {}> | Document<T, {}, {}>[], user?: User) {
    const serializeFn = (data: Document<T, {}, {}>, user?: User) => {
      const dataObject = data.toObject() as T;
      (dataObject as any).id = data._id;

      if (options.transformer?.serialize) {
        return options.transformer?.serialize(dataObject, user);
      } else {
        return dataObject;
      }
    };

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

    for (const queryParam of Object.keys(options.defaultQueryParams ?? [])) {
      query[queryParam] = (options.defaultQueryParams ?? {})[queryParam];
    }

    // TODO we can make this much more complicated with ands and ors, but for now, simple queries
    // will do.
    for (const queryParam of Object.keys(req.query)) {
      if ((options.queryFields ?? []).concat(SPECIAL_QUERY_PARAMS).includes(queryParam)) {
        // Not sure if this is necessary or if mongoose does the right thing.
        if (req.query[queryParam] === "true") {
          query[queryParam] = true;
        } else if (req.query[queryParam] === "false") {
          query[queryParam] = false;
        } else {
          query[queryParam] = req.query[queryParam];
        }
      } else {
        console.debug("Unallowed query param", queryParam);
        return res.status(400).json({message: `${queryParam} is not allowed as a query param.`});
      }
    }

    // Special operators. NOTE: these request Mongo Atlas.
    if (req.query["$search"]) {
      mongoose.connection.db.collection(model.collection.collectionName);
    }

    if (req.query["$autocomplete"]) {
      mongoose.connection.db.collection(model.collection.collectionName);
    }

    if (options.queryFilter) {
      query = {...query, ...options.queryFilter(req.user)};
    }

    let limit = options.defaultLimit ?? 100;
    if (req.query.limit && Number(req.query.limit) < (options.maxLimit ?? 500)) {
      limit = Number(req.query.limit);
    }

    let builtQuery = model.find(query).limit(limit);

    if (req.query.page) {
      builtQuery = builtQuery.skip((Number(req.query.page) - 1) * limit);
    }

    if (options.sort) {
      builtQuery = builtQuery.sort(options.sort);
    }

    // TODO: we should handle nested serializers here.
    for (const populatePath of options.populatePaths ?? []) {
      builtQuery = builtQuery.populate(populatePath);
    }

    let data: Document<T, {}, {}>[];
    try {
      data = await builtQuery.exec();
    } catch (e) {
      console.error("List error", e);
      return res.status(500).send();
    }
    // TODO add pagination
    try {
      return res.json({data: serialize(data, req.user)});
    } catch (e) {
      console.error("Serialization error", e);
      return res.status(500).send();
    }
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

  if (options.endpoints) {
    options.endpoints(router);
  }

  return router;
}
