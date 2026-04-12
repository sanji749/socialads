const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const SECRET = process.env.JWT_SECRET || "mysecretkey";

/* MIDDLEWARE */
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* MODELS */
const User = require("./models/User");
const Message = require("./models/Message");

/* DATABASE */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("DB ERROR:", err));

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

/* TEST ROUTE */
app.get("/test", (req, res) => {
  res.send("Server working");
});

/* HOME PAGE */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* SIGNUP */
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const oldUser = await User.findOne({ email });
    if (oldUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await new User({
      name,
      email,
      password: hash,
      role: "user"
    }).save();

    return res.status(201).json({
      message: "Signup successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error("SIGNUP ERROR:", error);
    return res.status(500).json({ message: error.message || "Signup failed" });
  }
});

/* LOGIN */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const valid = await bcrypt.compare(password, user.password);

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

    return res.json({
      message: "Login success",
      token,
      role: user.role,
      name: user.name,
      email: user.email
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    return res.status(500).json({ message: error.message || "Login failed" });
  }
});

/* DASHBOARD DATA */
app.get("/stats", auth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
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

    return res.json({
      totalUsers,
      totalMessages,
      latestMessages,
      campaignIdeas
    });
  } catch (error) {
    console.error("STATS ERROR:", error);
    return res.status(500).json({ message: error.message || "Failed to load dashboard stats" });
  }
});

/* ADMIN: VIEW ALL MESSAGES */
app.get("/messages", auth, adminOnly, async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 });
    return res.json(messages);
  } catch (error) {
    console.error("MESSAGES ERROR:", error);
    return res.status(500).json({ message: error.message || "Failed to fetch messages" });
  }
});

/* CONTACT */
app.post("/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;

    await Message.create({ name, email, message });

    return res.json({ message: "Message saved successfully" });
  } catch (error) {
    console.error("CONTACT ERROR:", error);
    return res.status(500).json({ message: error.message || "Failed to save message" });
  }
});

/* SERVER START */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});