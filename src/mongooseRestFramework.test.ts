import chai from "chai";
import express, {Express} from "express";
import mongoose, {model, ObjectId, Schema} from "mongoose";
import passportLocalMongoose from "passport-local-mongoose";
import supertest from "supertest";
import {
  AdminOwnerTransformer,
  createdDeletedPlugin,
  gooseRestRouter,
  Permissions,
  setupAuth,
  tokenPlugin,
} from "./mongooseRestFramework";

const assert = chai.assert;
const JWTOptions = {
  sessionSecret: "cats",
  jwtSecret: "secret",
  jwtIssuer: "example.com",
};
mongoose.connect("mongodb://localhost:27017/mrf");

interface User {
  admin: boolean;
  username: string;
  email: string;
}

interface Food {
  name: string;
  calories: number;
  created: Date;
  ownerId: mongoose.Types.ObjectId | User;
  hidden?: boolean;
}

const userSchema = new Schema<User>({
  username: String,
  admin: {type: Boolean, default: false},
});

userSchema.plugin(passportLocalMongoose, {usernameField: "email"});
userSchema.plugin(tokenPlugin);
userSchema.plugin(createdDeletedPlugin);

const UserModel = model<User>("User", userSchema);

const schema = new Schema<Food>({
  name: String,
  calories: Number,
  created: Date,
  ownerId: {type: "ObjectId", ref: "User"},
  hidden: {type: Boolean, default: false},
});

const FoodModel = model<Food>("Food", schema);

function getBaseServer(): Express {
  const app = express();

  app.all("/*", function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    //intercepts OPTIONS method
    if (req.method === "OPTIONS") {
      res.send(200);
    } else {
      next();
    }
  });
  app.use(express.json());
  return app;
}

afterAll(() => {
  mongoose.connection.close();
});

describe("mongoose rest framework", () => {
  let server: supertest.SuperTest<supertest.Test>;
  let app: express.Application;
  const OLD_ENV = process.env;

  beforeEach(function() {
    // jest.resetModules(); // Most important - it clears the cache
    process.env = {...OLD_ENV}; // Make a copy
    process.env.TOKEN_SECRET = "secret";
  });

  afterEach(function() {
    process.env = OLD_ENV;
  });

  describe("permissions", function() {
    beforeEach(async function() {
      await Promise.all([UserModel.deleteMany({}), FoodModel.deleteMany({})]);
      const [notAdmin, admin] = await Promise.all([
        UserModel.create({email: "notAdmin@example.com"}),
        UserModel.create({email: "admin@example.com", admin: true}),
      ]);
      await (notAdmin as any).setPassword("password");
      await notAdmin.save();

      await (admin as any).setPassword("securePassword");
      await admin.save();

      await Promise.all([
        FoodModel.create({
          name: "Spinach",
          calories: 1,
          created: new Date(),
          ownerId: notAdmin._id,
        }),
        FoodModel.create({
          name: "Apple",
          calories: 100,
          created: new Date().getTime() - 10,
          ownerId: admin._id,
        }),
      ]);
      app = getBaseServer();
      setupAuth(app, UserModel as any, JWTOptions);
      app.use(
        "/food",
        gooseRestRouter(FoodModel, {
          permissions: {
            list: [Permissions.IsAny],
            create: [Permissions.IsAuthenticated],
            read: [Permissions.IsAny],
            update: [Permissions.IsOwner],
            delete: [Permissions.IsAdmin],
          },
        })
      );
      server = supertest(app);
    });

    describe("anonymous food", function() {
      it("list", async function() {
        const res = await server.get("/food").expect(200);
        assert.lengthOf(res.body.data, 2);
      });

      it("get", async function() {
        const res = await server.get("/food").expect(200);
        assert.lengthOf(res.body.data, 2);
        const res2 = await server.get(`/food/${res.body.data[0]._id}`).expect(200);
        assert.equal(res.body.data[0]._id, res2.body.data._id);
      });

      it("post", async function() {
        const res = await server.post("/food").send({
          name: "Broccoli",
          calories: 15,
        });
        assert.equal(res.status, 405);
      });

      it("patch", async function() {
        const res = await server.get("/food");
        const res2 = await server.patch(`/food/${res.body.data[0]._id}`).send({
          name: "Broccoli",
        });
        assert.equal(res2.status, 403);
      });

      it("delete", async function() {
        const res = await server.get("/food");
        const res2 = await server.delete(`/food/${res.body.data[0]._id}`);
        assert.equal(res2.status, 405);
      });
    });

    describe("non admin food", function() {
      let agent: supertest.SuperAgentTest;
      let token: string;
      beforeEach(async function() {
        agent = supertest.agent(app);
        const res = await agent
          .post("/auth/login")
          .send({email: "notAdmin@example.com", password: "password"})
          .expect(200);
        token = res.body.data.token;
      });

      it("list", async function() {
        const res = await agent.get("/food").set("authorization", `Bearer ${token}`);
        assert.lengthOf(res.body.data, 2);
      });

      it("get", async function() {
        const res = await agent.get("/food").set("authorization", `Bearer ${token}`);
        assert.lengthOf(res.body.data, 2);
        const res2 = await agent
          .get(`/food/${res.body.data[0]._id}`)
          .set("authorization", `Bearer ${token}`);
        assert.equal(res.body.data[0]._id, res2.body.data._id);
      });

      it("post", async function() {
        const res = await agent
          .post("/food")
          .set("authorization", `Bearer ${token}`)
          .send({
            name: "Broccoli",
            calories: 15,
          });
        assert.equal(res.status, 200);
      });

      it("patch own item", async function() {
        const res = await agent.get("/food");
        const spinach = res.body.data.find((food: Food) => food.name === "Spinach");
        const res2 = await agent
          .patch(`/food/${spinach._id}`)
          .set("authorization", `Bearer ${token}`)
          .send({
            name: "Broccoli",
          });
        assert.equal(res2.status, 200);
        assert.equal(res2.body.data.name, "Broccoli");
      });

      it("patch other item", async function() {
        const res = await agent.get("/food");
        const spinach = res.body.data.find((food: Food) => food.name === "Apple");
        const res2 = await agent
          .patch(`/food/${spinach._id}`)
          .set("authorization", `Bearer ${token}`)
          .send({
            name: "Broccoli",
          });
        assert.equal(res2.status, 403);
      });

      it("delete", async function() {
        const res = await agent.get("/food");
        const res2 = await agent.delete(`/food/${res.body.data[0]._id}`);
        assert.equal(res2.status, 405);
      });
    });

    describe("admin food", function() {
      let agent: supertest.SuperAgentTest;
      let token: string;
      beforeEach(async function() {
        agent = supertest.agent(app);
        const res = await agent
          .post("/auth/login")
          .send({email: "admin@example.com", password: "securePassword"})
          .expect(200);
        token = res.body.data.token;
      });

      it("list", async function() {
        const res = await agent.get("/food");
        assert.lengthOf(res.body.data, 2);
      });

      it("get", async function() {
        const res = await agent.get("/food");
        assert.lengthOf(res.body.data, 2);
        const res2 = await agent.get(`/food/${res.body.data[0]._id}`);
        assert.equal(res.body.data[0]._id, res2.body.data._id);
      });

      it("post", async function() {
        const res = await agent
          .post("/food")
          .set("authorization", `Bearer ${token}`)
          .send({
            name: "Broccoli",
            calories: 15,
          });
        assert.equal(res.status, 200);
      });

      it("patch", async function() {
        const res = await agent.get("/food");
        const res2 = await agent
          .patch(`/food/${res.body.data[0]._id}`)
          .set("authorization", `Bearer ${token}`)
          .send({
            name: "Broccoli",
          });
        assert.equal(res2.status, 200);
      });

      it("delete", async function() {
        const res = await agent.get("/food");
        const res2 = await agent
          .delete(`/food/${res.body.data[0]._id}`)
          .set("authorization", `Bearer ${token}`);
        assert.equal(res2.status, 200);
      });
    });
  });

  describe("query and transform", function() {
    let notAdmin: any;
    let admin: any;

    beforeEach(async function() {
      await Promise.all([UserModel.deleteMany({}), FoodModel.deleteMany({})]);
      [notAdmin, admin] = await Promise.all([
        UserModel.create({email: "notAdmin@example.com"}),
        UserModel.create({email: "admin@example.com", admin: true}),
      ]);
      await (notAdmin as any).setPassword("password");
      await notAdmin.save();

      await (admin as any).setPassword("securePassword");
      await admin.save();

      await Promise.all([
        FoodModel.create({
          name: "Spinach",
          calories: 1,
          created: new Date(),
          ownerId: notAdmin._id,
        }),
        FoodModel.create({
          name: "Apple",
          calories: 100,
          created: new Date().getTime() - 10,
          ownerId: admin._id,
          hidden: true,
        }),
        FoodModel.create({
          name: "Carrots",
          calories: 100,
          created: new Date().getTime() - 10,
          ownerId: admin._id,
        }),
      ]);
      app = getBaseServer();
      setupAuth(app, UserModel as any, JWTOptions);
      app.use(
        "/food",
        gooseRestRouter(FoodModel, {
          permissions: {
            list: [Permissions.IsAny],
            create: [Permissions.IsAny],
            read: [Permissions.IsAny],
            update: [Permissions.IsAny],
            delete: [Permissions.IsAny],
          },
          queryFilter: (user?: {_id: ObjectId | string; admin: boolean}) => {
            if (!user?.admin) {
              return {hidden: {$ne: true}};
            }
            return {};
          },
          transformer: AdminOwnerTransformer<Food>({
            adminReadFields: ["name", "calories", "created", "ownerId"],
            adminWriteFields: ["name", "calories", "created", "ownerId"],
            ownerReadFields: ["name", "calories", "created", "ownerId"],
            ownerWriteFields: ["name", "calories", "created"],
            authReadFields: ["name", "calories", "created"],
            authWriteFields: ["name", "calories"],
            anonReadFields: ["name"],
            anonWriteFields: [],
          }),
        })
      );
      server = supertest(app);
    });

    it("filters list for non-admin", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      assert.lengthOf(foodRes.body.data, 2);
    });

    it("does not filter list for admin", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "admin@example.com", password: "securePassword"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      assert.lengthOf(foodRes.body.data, 3);
    });

    it("admin read transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "admin@example.com", password: "securePassword"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      assert.lengthOf(foodRes.body.data, 3);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      assert.isDefined(spinach.created);
      assert.isDefined(spinach.id);
      assert.isDefined(spinach.ownerId);
      assert.equal(spinach.name, "Spinach");
      assert.equal(spinach.calories, 1);
      assert.isUndefined(spinach.hidden);
    });

    it("admin write transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "admin@example.com", password: "securePassword"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      const spinachRes = await agent
        .patch(`/food/${spinach.id}`)
        .set("authorization", `Bearer ${res.body.data.token}`)
        .send({name: "Lettuce"})
        .expect(200);
      assert.equal(spinachRes.body.data.name, "Lettuce");
    });

    it("owner read transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      assert.lengthOf(foodRes.body.data, 2);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      assert.isDefined(spinach.id);
      assert.equal(spinach.name, "Spinach");
      assert.equal(spinach.calories, 1);
      assert.isDefined(spinach.created);
      assert.isDefined(spinach.ownerId);
      assert.isUndefined(spinach.hidden);
    });

    it("owner write transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      await agent
        .patch(`/food/${spinach.id}`)
        .send({ownerId: admin.id})
        .expect(403);
    });

    it("owner write transform fails", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      const spinachRes = await agent
        .patch(`/food/${spinach.id}`)
        .set("authorization", `Bearer ${res.body.data.token}`)
        .send({ownerId: notAdmin.id})
        .expect(403);
      assert.equal(spinachRes.body.message, "User of type owner cannot write fields: ownerId");
    });

    it("auth read transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent
        .get("/food")
        .set("authorization", `Bearer ${res.body.data.token}`)
        .expect(200);
      assert.lengthOf(foodRes.body.data, 2);
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      assert.isDefined(spinach.id);
      assert.equal(spinach.name, "Spinach");
      assert.equal(spinach.calories, 1);
      assert.isDefined(spinach.created);
      // Owner, so this is defined.
      assert.isDefined(spinach.ownerId);
      assert.isUndefined(spinach.hidden);

      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      assert.isDefined(carrots.id);
      assert.equal(carrots.name, "Carrots");
      assert.equal(carrots.calories, 100);
      assert.isDefined(carrots.created);
      // Not owner, so undefined.
      assert.isUndefined(carrots.ownerId);
      assert.isUndefined(spinach.hidden);
    });

    it("auth write transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      console.log("RES", res.body);
      const foodRes = await agent.get("/food");
      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      const carrotRes = await agent
        .patch(`/food/${carrots.id}`)
        .set("authorization", `Bearer ${res.body.data.token}`)
        .send({calories: 2000})
        .expect(200);
      assert.equal(carrotRes.body.data.calories, 2000);
    });

    it("auth write transform fail", async function() {
      const agent = supertest.agent(app);
      const res = await agent
        .post("/auth/login")
        .send({email: "notAdmin@example.com", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      const writeRes = await agent
        .patch(`/food/${carrots.id}`)
        .set("authorization", `Bearer ${res.body.data.token}`)
        .send({created: "2020-01-01T00:00:00Z"})
        .expect(403);
      assert.equal(writeRes.body.message, "User of type auth cannot write fields: created");
    });

    it("anon read transform", async function() {
      const agent = supertest.agent(app);
      const res = await agent.get("/food");
      assert.lengthOf(res.body.data, 2);
      assert.isDefined(res.body.data.find((f: Food) => f.name === "Spinach"));
      assert.isDefined(res.body.data.find((f: Food) => f.name === "Carrots"));
    });

    it("anon write transform fails", async function() {
      const agent = supertest.agent(app);
      const foodRes = await agent.get("/food");
      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      await agent
        .patch(`/food/${carrots.id}`)
        .send({calories: 10})
        .expect(403);
    });
  });

  let spinach: Food;
  let apple: Food;
  let carrots: Food;

  describe("list options", function() {
    let notAdmin: any;
    let admin: any;

    beforeEach(async function() {
      await Promise.all([UserModel.deleteMany({}), FoodModel.deleteMany({})]);
      [notAdmin, admin] = await Promise.all([
        UserModel.create({email: "notAdmin@example.com"}),
        UserModel.create({email: "admin@example.com", admin: true}),
      ]);
      await (notAdmin as any).setPassword("password");
      await notAdmin.save();

      await (admin as any).setPassword("securePassword");
      await admin.save();

      [spinach, apple, carrots] = await Promise.all([
        FoodModel.create({
          name: "Spinach",
          calories: 1,
          created: new Date(),
          ownerId: notAdmin._id,
          hidden: false,
        }),
        FoodModel.create({
          name: "Apple",
          calories: 100,
          created: new Date().getTime() - 10,
          ownerId: admin._id,
          hidden: true,
        }),
        FoodModel.create({
          name: "Carrots",
          calories: 100,
          created: new Date().getTime() - 20,
          ownerId: admin._id,
          hidden: false,
        }),
      ]);
      app = getBaseServer();
      setupAuth(app, UserModel as any, JWTOptions);
      app.use(
        "/food",
        gooseRestRouter(FoodModel, {
          permissions: {
            list: [Permissions.IsAny],
            create: [Permissions.IsAuthenticated],
            read: [Permissions.IsAny],
            update: [Permissions.IsOwner],
            delete: [Permissions.IsAdmin],
          },
          defaultLimit: 2,
          maxLimit: 2,
          sort: {created: "descending"},
          defaultQueryParams: {hidden: false},
          queryFields: ["hidden", "calories"],
          populatePaths: ["ownerId"],
        })
      );
      server = supertest(app);
    });

    it("list limit", async function() {
      const res = await server.get("/food?limit=1").expect(200);
      assert.lengthOf(res.body.data, 1);
      assert.equal(res.body.data[0].id, (spinach as any).id);
      assert.equal(res.body.data[0].ownerId._id, notAdmin.id);
    });

    it("list limit over", async function() {
      const res = await server.get("/food?limit=4").expect(200);
      assert.lengthOf(res.body.data, 2);
      assert.equal(res.body.data[0].id, (spinach as any).id);
      assert.equal(res.body.data[1].id, (carrots as any).id);
    });

    it("list page", async function() {
      // Should skip to carrots since apples are hidden
      const res = await server.get("/food?limit=1&page=2").expect(200);
      assert.lengthOf(res.body.data, 1);
      assert.equal(res.body.data[0].id, (carrots as any).id);
    });

    it("list page over", async function() {
      // Should skip to carrots since apples are hidden
      const res = await server.get("/food?limit=1&page=4").expect(200);
      assert.lengthOf(res.body.data, 0);
    });

    it("list query params", async function() {
      // Should skip to carrots since apples are hidden
      const res = await server.get("/food?hidden=true").expect(200);
      assert.lengthOf(res.body.data, 1);
      assert.equal(res.body.data[0].id, (apple as any).id);
    });

    it("list query params not in list", async function() {
      // Should skip to carrots since apples are hidden
      const res = await server.get("/food?name=Apple").expect(400);
      assert.equal(res.body.message, "name is not allowed as a query param.");
    });
  });
});

describe("test token auth", function() {
  let app;
  let server: any;
  const OLD_ENV = process.env;

  beforeEach(function() {
    // jest.resetModules(); // Most important - it clears the cache
    process.env = {...OLD_ENV}; // Make a copy
    process.env.TOKEN_SECRET = "secret";
  });

  afterEach(function() {
    process.env = OLD_ENV;
  });

  beforeEach(async function() {
    await Promise.all([UserModel.deleteMany({}), FoodModel.deleteMany({})]);

    const [notAdmin, admin] = await Promise.all([
      UserModel.create({email: "notAdmin@example.com"}),
      UserModel.create({email: "admin@example.com", admin: true}),
    ]);

    await (notAdmin as any).setPassword("password");
    await notAdmin.save();

    await (admin as any).setPassword("securePassword");
    await admin.save();

    await Promise.all([
      FoodModel.create({
        name: "Spinach",
        calories: 1,
        created: new Date(),
        ownerId: notAdmin._id,
      }),
      FoodModel.create({
        name: "Apple",
        calories: 100,
        created: new Date().getTime() - 10,
        ownerId: admin._id,
        hidden: true,
      }),
      FoodModel.create({
        name: "Carrots",
        calories: 100,
        created: new Date().getTime() - 10,
        ownerId: admin._id,
      }),
    ]);
    app = getBaseServer();
    setupAuth(app, UserModel as any, JWTOptions);
    app.use(
      "/food",
      gooseRestRouter(FoodModel, {
        permissions: {
          list: [Permissions.IsAny],
          create: [Permissions.IsAuthenticated],
          read: [Permissions.IsAny],
          update: [Permissions.IsAuthenticated],
          delete: [Permissions.IsAuthenticated],
        },
        queryFilter: (user?: {admin: boolean}) => {
          if (!user?.admin) {
            return {hidden: {$ne: true}};
          }
          return {};
        },
        transformer: AdminOwnerTransformer<Food>({
          adminReadFields: ["name", "calories", "created", "ownerId"],
          adminWriteFields: ["name", "calories", "created", "ownerId"],
          ownerReadFields: ["name", "calories", "created", "ownerId"],
          ownerWriteFields: ["name", "calories", "created"],
          authReadFields: ["name", "calories", "created"],
          authWriteFields: ["name", "calories"],
          anonReadFields: ["name"],
          anonWriteFields: [],
        }),
      })
    );
    server = supertest(app);
  });

  it("completes token signup e2e", async function() {
    let res = await server
      .post("/auth/signup")
      .send({email: "new@example.com", password: "123"})
      .expect(200);
    let {userId, token} = res.body.data;
    assert.isDefined(userId);
    assert.isDefined(token);

    res = await server
      .post("/auth/login")
      .send({email: "new@example.com", password: "123"})
      .expect(200);
    userId = res.body.data.userId;
    token = res.body.data.token;
    assert.isDefined(userId);
    assert.isDefined(token);

    const food = await FoodModel.create({
      name: "Peas",
      calories: 1,
      created: new Date(),
      ownerId: userId,
    });

    // Use token to see 2 foods + the one we just created
    const getRes = await server
      .get("/food")
      .set("authorization", `Bearer ${token}`)
      .expect(200);

    assert.lengthOf(getRes.body.data, 3);
    assert.isDefined(getRes.body.data.find((f: any) => f.name === "Peas"));

    const updateRes = await server
      .patch(`/food/${food._id}`)
      .set("authorization", `Bearer ${token}`)
      .send({name: "PeasAndCarrots"})
      .expect(200);
    assert.equal(updateRes.body.data.name, "PeasAndCarrots");
  });

  it("completes token login e2e", async function() {
    const res = await server
      .post("/auth/login")
      .send({email: "admin@example.com", password: "securePassword"})
      .expect(200);
    const {userId, token} = res.body.data;
    assert.isDefined(userId);
    assert.isDefined(token);

    // Use token to see admin foods
    const getRes = await server
      .get("/food")
      .set("Authorization", `Bearer ${token}`)
      .expect(200);

    assert.lengthOf(getRes.body.data, 3);
    const food = getRes.body.data.find((f: any) => f.name === "Apple");
    assert.isDefined(food);

    const updateRes = await server
      .patch(`/food/${food.id}`)
      .set("authorization", `Bearer ${token}`)
      .send({name: "Apple Pie"})
      .expect(200);
    assert.equal(updateRes.body.data.name, "Apple Pie");
  });
});
