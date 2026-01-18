const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    number: { type: Number, required: true, unique: true },
    role: {
      type: String,
      enum: ["admin", "normal"], // restricts values
      default: "normal"
    }
  },
  {
    collection: "user",   // ✅ merged options
    timestamps: true      // ✅ merged options
  }
);

// Prevent model overwrite in serverless environments
const User = mongoose.models.user || mongoose.model("user", userSchema);

module.exports = User;