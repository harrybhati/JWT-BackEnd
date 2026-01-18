// Load env variables only for local development
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const connectDb = require("./DB/Config");
const User = require("./DB/UserSchema");

const app = express();

// ================= MIDDLEWARES =================
const cors = require("cors");

app.use(cors({
  origin: [
    "http://localhost:5173",                 // local dev
    "https://jwt-front-end-gilt.vercel.app"  // deployed frontend
  ],
  credentials: true, // allow cookies
}));

app.use(express.json());
app.use(cookieParser());

// ================= SERVERLESS-FRIENDLY DB CONNECT =================
app.use(async (req, res, next) => {
  try {
    await connectDb();
    next();
  } catch (err) {
    console.error("Database connection error:", err);
    res.status(500).json({ message: "Database connection failed" });
  }
});

// ================= ROOT ROUTE =================
app.get("/", (req, res) => {
  res.json({ message: "JWT Backend API is running!" });
});

// ================= AUTH MIDDLEWARE =================
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ================= SIGNUP =================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, number, role } = req.body;

    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ message: "User already registered" });

    const hashedPassword = await bcrypt.hash(password.toString(), 10);

    const newUser = new User({ name, email, number, password: hashedPassword, role });
    await newUser.save();

    const token = jwt.sign({ id: newUser._id, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "none" });

    res.status(201).json({
      message: "User created",
      user: { id: newUser._id, name: newUser.name, email: newUser.email, number: newUser.number, role: newUser.role },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password.toString(), user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "none" });

    res.status(200).json({
      message: "Login successful",
      user: { id: user._id, name: user.name, email: user.email, number: user.number, role: user.role },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ================= CHECK AUTH =================
app.get("/checkAuth", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("role");
    if (!user) return res.status(401).json({ message: "User not found" });

    res.status(200).json({ message: "Authenticated", role: user.role });
  } catch (err) {
    console.error("CheckAuth error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ================= LOGOUT =================
app.post("/logout", (req, res) => {
  res.clearCookie("token", { httpOnly: true, secure: true, sameSite: "none" });
  res.status(200).json({ message: "Logout successful" });
});

// ================= EXPORT APP =================
module.exports = app;