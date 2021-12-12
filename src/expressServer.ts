import * as Sentry from "@sentry/node";
import axios from "axios";
import cron from "cron";
import express, {Router} from "express";
import cloneDeep from "lodash/cloneDeep";
import {Env, setupAuth, UserModel} from "./mongooseRestFramework";
import onFinished from "on-finished";
import passport from "passport";

const SLOW_READ_MAX = 200;
const SLOW_WRITE_MAX = 500;

const dsn = (process.env as Env).SENTRY_DSN;
if (process.env.NODE_ENV === "production") {
  if (!dsn) {
    throw new Error("You must set SENTRY_DSN in the environment.");
  }
  Sentry.init({dsn});
}

export type AddRoutes = (router: Router) => void;

const logRequestsFinished = function(req: any, res: any, startTime: [number, number]) {
  const diff = process.hrtime(startTime);
  const diffInMs = Math.round(diff[0] * 1000 + diff[1] * 0.000001);
  let pathName = "unknown";
  if (req.route && req.routeMount) {
    pathName = `${req.routeMount}${req.route.path}`;
  } else if (req.route) {
    pathName = req.route.path;
  } else if (res.statusCode < 400) {
    console.warn(`Request without route: ${req.originalUrl}`);
  }

  console.debug(`${req.method} -> ${req.originalUrl} ${res.statusCode} ${diffInMs + "ms"}`);
  if (diffInMs > SLOW_READ_MAX && req.method === "GET") {
    console.warn("Slow GET request", {
      requestTime: diffInMs,
      pathName: pathName,
      url: req.originalUrl,
    });
  } else if (diffInMs > SLOW_WRITE_MAX) {
    console.warn("Slow write request", {
      requestTime: diffInMs,
      pathName: pathName,
      url: req.originalUrl,
    });
  }
};

function logRequests(req: any, res: any, next: any) {
  const startTime = process.hrtime();

  let userString = "";
  if (req.user) {
    userString = ` <${req.user?.admin ? "Admin" : req.user?.testUser ? "Test User" : "User"}:${
      req.user.id
    }>`;
  }

  let body = "";
  if (req.body && Object.keys(req.body).length > 0) {
    const bodyCopy = cloneDeep(req.body);
    if (bodyCopy.password) {
      bodyCopy.password = "<PASSWORD>";
    }
    body = ` Body: ${JSON.stringify(bodyCopy)}`;
  }

  console.debug(`${req.method} <- ${req.url}${userString}${body}`);
  onFinished(res, () => logRequestsFinished(req, res, startTime));
  next();
}

export function createRouter(
  rootPath: string,
  addRoutes: (router: Router) => void,
  middleware: any[] = []
) {
  function routePathMiddleware(req: any, res: any, next: any) {
    if (!req.routeMount) {
      req.routeMount = [];
    }
    req.routeMount.push(rootPath);
    next();
  }

  const router = express.Router();
  router.use(routePathMiddleware);
  addRoutes(router);
  return [rootPath, ...middleware, router];
}

export function createRouterWithAuth(
  rootPath: string,
  addRoutes: (router: Router) => void,
  middleware: any[] = []
) {
  return createRouter(rootPath, addRoutes, [
    passport.authenticate("firebase-jwt", {session: false}),
    ...middleware,
  ]);
}

function initializeRoutes(UserModel: UserModel, addRoutes: AddRoutes) {
  if (!process.env.SESSION_SECRET && process.env.NODE_ENV === "production") {
    throw new Error("You must provide a SESSION_SECRET in env.");
  }

  const app = express();

  app.use(Sentry.Handlers.requestHandler());

  app.all("/*", function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    if (req.method === "OPTIONS") {
      res.send(200);
    } else {
      next();
    }
  });

  app.use(express.json());

  app.use(logRequests);

  setupAuth(app as any, UserModel as any);

  // Adds all the user
  addRoutes(app);

  // The error handler must be before any other error middleware and after all controllers
  app.use(Sentry.Handlers.errorHandler());

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use(function onError(_err: any, _req: any, res: any, _next: any) {
    console.error("Fallthrough error", _err);
    res.statusCode = 500;
    res.end(res.sentry + "\n");
  });

  console.debug("Listening on routes:");
  app._router.stack.forEach((r: any) => {
    if (r.route && r.route.path) {
      console.debug("[Route] " + r.route.path);
    }
  });

  return app;
}

// Sets up the routes and returns a function to launch the API.
export function setupServer(UserModel: UserModel, addRoutes: AddRoutes) {
  let app: express.Application;
  try {
    app = initializeRoutes(UserModel, addRoutes);
  } catch (e) {
    console.error("Error initializing routes", e);
    throw e;
  }

  return () => {
    const port = process.env.PORT || "9000";
    try {
      app.listen(port, () => {
        console.info(`Listening at on port ${port}`);
      });
    } catch (err) {
      console.error(`Error trying to start HTTP server: ${err}\n${(err as any).stack}`);
      process.exit(1);
    }
  };
}

// Convenince method to execute cronjobs with an always-running server.
export function cronjob(name: string, schedule: "hourly" | string, callback: () => void) {
  if (schedule === "hourly") {
    schedule = "0 * * * *";
  }
  console.info(`Adding cronjob ${name}, running at: ${schedule}`);
  try {
    new cron.CronJob({
      cronTime: schedule,
      onTick: callback,
      start: true,
      timeZone: "America/Chicago",
    });
  } catch (e) {
    throw new Error(`Failed to create cronjob: ${e}`);
  }
}

// Convenience method to send data to a Slack webhook.
export async function sendToSlack(text: string, channel = "bots") {
  const slackWebhookUrl = (process.env as Env).SLACK_WEBHOOK;
  if (!slackWebhookUrl) {
    throw new Error("You must set SLACK_WEBHOOK in the environment.");
  }
  try {
    await axios.post(slackWebhookUrl, {
      text,
      channel,
    });
  } catch (e) {
    console.error("Error posting to slack", (e as any).text);
  }
}
