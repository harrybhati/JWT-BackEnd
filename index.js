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

// ================= DATABASE =================
connectDb();

// ================= MIDDLEWARES =================
app.use(cors({
  origin: true,          // ✅ allow any origin for now
  credentials: true,     // ✅ required for cookies
}));

app.use(express.json());
app.use(cookieParser());

// ================= AUTH MIDDLEWARE =================
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

app.get("/", (req, res) => {
  res.send("JWT Backend API is running! Use /signup, /login, /checkAuth endpoints.");
});


// ================= SIGNUP =================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, number, role } = req.body;

    const userExist = await User.findOne({ email });
    if (userExist) {
      return res.status(400).json({ message: "User already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      number,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,        // ✅ required on Vercel (HTTPS)
      sameSite: "none",    // ✅ required for cross-site cookies
    });

    res.status(201).json({
      message: "User created",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        number: newUser.number,
        role: newUser.role,
      },
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
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        number: user.number,
        role: user.role,
      },
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
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "Authenticated",
      role: user.role,
    });
  } catch (err) {
    console.error("CheckAuth error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ================= LOGOUT =================
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  res.status(200).json({ message: "Logout successful" });
});

// ================= EXPORT APP (Vercel requires this) =================
module.exports = app;
