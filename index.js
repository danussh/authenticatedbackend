const express = require("express");
const mongodb = require("mongodb");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const port = process.env.PORT || 3001;
const jwt = require("jsonwebtoken");

const mongoClient = mongodb.MongoClient;
var objectId = require("mongodb").ObjectId;
const app = express();
dotenv.config();
app.use(express.json());
app.use(cors());

const dbURL = process.env.DB_URL; //Mongo DB URL

// MiddleWare To verify Token
const verifyJwt = async (req, res, next) => {
  const token = await req.header("auth-token");
  if (!token) {
    res.send("Access Denied");
  } else {
    jwt.verify(token, process.env.SECRET, (err, decode) => {
      if (err) {
        res.json({ message: "Failed To Authenticate" });
      } else {
        req.user = decode.id;
        next();
      }
    });
  }
};

// GET all employess details
app.get("/employess", verifyJwt, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("employess-details");
    let data = await db.collection("employess").find().toArray();
    res.status(200).json(data);
    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

//POST employes details
app.post("/add-employee", verifyJwt, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("employess-details");
    let data = await db.collection("employess").insertOne(req.body);
    res.status(200).json({
      message: "Employee created",
    });
    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

//Edit employee details by id
app.put("/edit-employee/:id", verifyJwt, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("employess-details");
    let data = await db.collection("employess").updateOne(
      {
        _id: objectId(req.params.id),
      },
      {
        $set: req.body,
      }
    );
    res.status(200).send({
      message: "Employee updated",
    });
    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

//Delete employee-details details by id
app.delete("/delete-user/:id", verifyJwt, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("employess-details");
    let data = await db.collection("employess").deleteOne({
      _id: objectId(req.params.id),
    });
    res.status(200).send({
      message: "employess-details deleted",
    });
    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

//TO search a collection in DB for email name phone and address
app.get("/search/:key", verifyJwt, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("employess-details");
    let data = await db
      .collection("employess")
      .find({
        $or: [
          { name: new RegExp(req.params.key, "i") },
          { email: new RegExp(req.params.key, "i") },
          { phone: new RegExp(req.params.key, "i") },
          { address: new RegExp(req.params.key, "i") },
        ],
      })
      .toArray();
    res.send(data);
    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

// To Register a Employee

app.post("/register", async (req, res) => {
  var user = req.body;
  var hash = await bcrypt.hash(user.password, 10);
  user.password = hash;
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    const db = clientInfo.db("employess-details");
    const data = await db.collection("users").insertOne(user);
    await clientInfo.close();
    res.json({ message: "registration successful", data: data });
  } catch (err) {
    console.log(err);
    res.json({ message: "failed" });
  }
});

// TO Login the Registed User and Get The Registered User generate Token on login

app.post("/login", async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    const db = clientInfo.db("employess-details");
    const data = await db
      .collection("users")
      .findOne({ email: req.body.email });
    if (data) {
      var match = await bcrypt.compare(req.body.password, data.password);
      if (match) {
        const id = data._id.valueOf();
        await clientInfo.close();

        const token = jwt.sign({ id }, process.env.SECRET, {
          expiresIn: "12h",
        });
        res.json({ message: "login successful", data: data, token: token });
      } else {
        res.status(401).json({
          message: "password did not match",
        });
      }
    } else {
      res.status(400).json({
        message: "Email not found",
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "failed" });
  }
});

app.listen(port, () => console.log("your app runs with port:" + port));
