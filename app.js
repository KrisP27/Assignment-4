const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("./models/User");
const validator = require("validator");

const app = express();
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("DB Connected");
  })
  .catch((e) => {
    console.error("DB Error", e);
  });

const signAccessToken = (userid) => {
  console.log("Signing Access Token for userId: ", userid);
  console.log("JWT", process.env.JWT_SECRET);
  console.log("JWT_EXPIRES_IN", process.env.JWT_EXPIRES_IN);
  const token =  jwt.sign({ sub: userid }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
  console.log("token generated", token);
  return token;
};

//Authorization
const requireAuth = (req, res, next) => {
    try{
        const header = req.headers["authorization"];

        if (!header || !header.startsWith("Bearer "))
        {
          return res.status(401).json({
            status: "error",
            error: {
              code: "INVALID_TOKEN",
              message: "Invalid Token"
            }
          });  
        }

        const token = header.split(" ")[1];
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = payload.sub;

        return next();
    }

    catch(error)
    {
        return res.status(401).json({
          status: "error",
          error: {
            code: "INVALID_TOKEN",
            message: "Invalid Token"
          }
        });
    }
};

//Signing Up
app.post("/users/signup", async (req, res) => {
  try {
    let { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ 
          status: "error",
          error: "Requirement Missing" 
        });
    }

    //Normalize the Email
    const normalizedEmail = validator.normalizeEmail(email);

    //Check for Unique Email
    const exists = await User.findOne({ email: normalizedEmail });
    if (exists) {
      return res.status(400).json({ 
        status: "error",
        error: {
          code: "DUPLICATE_EMAIL",
          message: "Email is already registered" 
        }
      });
    }

    //Hashing Password
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({ 
      email: normalizedEmail, 
      name, 
      passwordHash 
    });
    
    return res.status(201).json({
      status: "ok",
      data: { userId: user._id }
    });
  } 
  
  catch (error) {
    return res.status(500).json({ 
      status: "error",
      error: error});
  }
});

//Logging In
app.post("/users/login", async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        status: "error",
        error: {
          code: "INVALID_INPUT",
          message: "Requirement Missing"
        } 
      });
    }

    const normalizedEmail = validator.normalizeEmail(email);

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(400).json({ 
        status: "error",
        error: {
          code: "EMAIL_NOT_FOUND",
          message: "Email not found"
        } 
      });
    }

    console.log("User found");
    console.log(user);

    const isPasswordMatch = await bcrypt.compare(password, user.passwordHash);

    if (isPasswordMatch) {
      // User is Authenticated
      console.log("User Authenticated");
      const token = signAccessToken(user._id);
      return res.status(200).json({
        status: "ok",
        data: {
          accessToken: token,
          tokenType: "Bearer",
          expiresIn: Number(process.env.JWT_EXPIRES_IN)
        }
      });
    } 
    
    else {
      return res.status(401).json({ 
        status: "error",
        error: {
          code: "BAD_PASSWORD",
          message: "Incorrect password" 
        }
      });
    }
  } 
  
  catch (error) {
    return res.status(500).json({
      status: "error",
      error: error
    });
  }
});

app.get("/me", requireAuth, async (req, res) => {

  try {

    const user = await User.findById(req.userId).lean();

    if (!user) {
      return res.status(401).json({
        status: "error",
        error: {
          code: "INVALID_TOKEN",
          message: "Invalid Token"
        }
      });
    }

    else {
      return res.status(200).json({
        status: "ok",
        data: {
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          createdAt: user.createdAt
        }
      }
    });
    }
  }

  catch (error) {
    return res.status(500).json ({
      status: "error",
      error: error
    });
  }
});

app.listen(process.env.PORT,  () => {
  console.log("App running on port: ", process.env.PORT);
});