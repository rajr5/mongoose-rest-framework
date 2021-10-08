import chai from "chai";
import express, {Express} from "express";
import mongoose, {model, Schema} from "mongoose";
import passportLocalMongoose from "passport-local-mongoose";
import supertest from "supertest";
import {
  AdminOwnerTransformer,
  gooseRestRouter,
  Permissions,
  setupAuth,
} from "./mongooseRestFramework";

mongoose.connect("mongodb://localhost:27017/testAvo");

const assert = chai.assert;

interface User {
  admin: boolean;
  username: string;
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

userSchema.plugin(passportLocalMongoose);

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

describe("goose", () => {
  let server: supertest.SuperTest<supertest.Test>;
  let app: express.Application;

  afterAll(() => {
    mongoose.connection.close();
  });

  describe("permissions", function() {
    beforeEach(async function() {
      await Promise.all([UserModel.deleteMany({}), FoodModel.deleteMany({})]);
      const [notAdmin, admin] = await Promise.all([
        UserModel.create({username: "notAdmin"}),
        UserModel.create({username: "admin", admin: true}),
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
      setupAuth(app, {sessionSecret: "cats"});
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
        const res = await server.get("/food");
        assert.lengthOf(res.body.data, 2);
      });

      it("get", async function() {
        const res = await server.get("/food");
        assert.lengthOf(res.body.data, 2);
        const res2 = await server.get(`/food/${res.body.data[0]._id}`);
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
      beforeEach(async function() {
        agent = supertest.agent(app);
        await agent
          .post("/auth/login")
          .send({username: "notAdmin", password: "password"})
          .expect(200);
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
        const res = await agent.post("/food").send({
          name: "Broccoli",
          calories: 15,
        });
        assert.equal(res.status, 200);
      });

      it("patch own item", async function() {
        const res = await agent.get("/food");
        const spinach = res.body.data.find((food: Food) => food.name === "Spinach");
        const res2 = await agent.patch(`/food/${spinach._id}`).send({
          name: "Broccoli",
        });
        assert.equal(res2.status, 200);
        assert.equal(res2.body.data.name, "Broccoli");
      });

      it("patch other item", async function() {
        const res = await agent.get("/food");
        const spinach = res.body.data.find((food: Food) => food.name === "Apple");
        const res2 = await agent.patch(`/food/${spinach._id}`).send({
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
      beforeEach(async function() {
        agent = supertest.agent(app);
        await agent
          .post("/auth/login")
          .send({username: "admin", password: "securePassword"})
          .expect(200);
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
        const res = await agent.post("/food").send({
          name: "Broccoli",
          calories: 15,
        });
        assert.equal(res.status, 200);
      });

      it("patch", async function() {
        const res = await agent.get("/food");
        const res2 = await agent.patch(`/food/${res.body.data[0]._id}`).send({
          name: "Broccoli",
        });
        assert.equal(res2.status, 200);
      });

      it("delete", async function() {
        const res = await agent.get("/food");
        const res2 = await agent.delete(`/food/${res.body.data[0]._id}`);
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
        UserModel.create({username: "notAdmin"}),
        UserModel.create({username: "admin", admin: true}),
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
      setupAuth(app, {sessionSecret: "cats"});
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

    it("filters list for non-admin", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const res = await agent.get("/food");
      assert.lengthOf(res.body.data, 2);
    });

    it("does not filter list for admin", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "admin", password: "securePassword"})
        .expect(200);
      const res = await agent.get("/food");
      assert.lengthOf(res.body.data, 3);
    });

    it("admin read transform", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "admin", password: "securePassword"})
        .expect(200);
      const foodRes = await agent.get("/food");
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
      await agent
        .post("/auth/login")
        .send({username: "admin", password: "securePassword"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      const spinachRes = await agent
        .patch(`/food/${spinach.id}`)
        .send({name: "Lettuce"})
        .expect(200);
      assert.equal(spinachRes.body.data.name, "Lettuce");
    });

    it("owner read transform", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
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
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      await agent
        .patch(`/food/${spinach.id}`)
        .send({ownerId: admin.id})
        .expect(403);
    });

    it("owner write transform fails", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const spinach = foodRes.body.data.find((food: Food) => food.name === "Spinach");
      const spinachRes = await agent
        .patch(`/food/${spinach.id}`)
        .send({ownerId: notAdmin.id})
        .expect(403);
      assert.equal(spinachRes.body.message, "User of type owner cannot write fields: ownerId");
    });

    it("auth read transform", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
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
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      const carrotRes = await agent
        .patch(`/food/${carrots.id}`)
        .send({calories: 2000})
        .expect(200);
      assert.equal(carrotRes.body.data.calories, 2000);
    });

    it("auth write transform fail", async function() {
      const agent = supertest.agent(app);
      await agent
        .post("/auth/login")
        .send({username: "notAdmin", password: "password"})
        .expect(200);
      const foodRes = await agent.get("/food");
      const carrots = foodRes.body.data.find((food: Food) => food.name === "Carrots");
      await agent
        .patch(`/food/${carrots.id}`)
        .send({created: "2020-01-01T00:00:00Z"})
        .expect(403);
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
});
