const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const SECRET = "mysecretkey";

/* MIDDLEWARE */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cors());

/* DATABASE */
mongoose.connect("mongodb://127.0.0.1:27017/marketingDB")
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

/* MODELS */
const User = require("./models/User");
const Message = require("./models/Message"); // (optional for dashboard only)

/* AUTH MIDDLEWARE */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "Access denied. No token." });
  }

  const token = header.startsWith("Bearer ")
    ? header.split(" ")[1]
    : header;

  try {
    const verified = jwt.verify(token, SECRET);
    req.user = verified;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/* ADMIN CHECK */
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }
  next();
}

/* HOME PAGE */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* SIGNUP */
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const oldUser = await User.findOne({ email });
    if (oldUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    await new User({
      name,
      email,
      password: hash,
      role: "user"
    }).save();

    res.json({ message: "Signup successful" });
  } catch (error) {
    res.status(500).json({ message: "Signup failed" });
  }
});

/* LOGIN */
app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const valid = await bcrypt.compare(req.body.password, user.password);

    if (!valid) {
      return res.status(400).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        email: user.email,
        name: user.name
      },
      SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login success",
      token,
      role: user.role,
      name: user.name
    });
  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});

/* DASHBOARD DATA */
app.get("/stats", auth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();

    // OPTIONAL (if you still use Message model)
    const totalMessages = await Message.countDocuments();

    const latestMessages = await Message.find()
      .sort({ createdAt: -1 })
      .limit(5);

    const campaignIdeas = [
      "Facebook Lead Generation Campaign",
      "Instagram Reels Brand Awareness",
      "YouTube Skippable Video Ads",
      "Email Marketing Funnel Campaign",
      "Twitter Event Promotion Strategy"
    ];

    res.json({
      totalUsers,
      totalMessages,
      latestMessages,
      campaignIdeas
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to load dashboard stats" });
  }
});

/* ADMIN: VIEW ALL MESSAGES (OPTIONAL) */
app.get("/messages", auth, adminOnly, async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});

/* SERVER START */
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});