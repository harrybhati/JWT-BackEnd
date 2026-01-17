const mongoose = require("mongoose");

let isConnected = false;

const connectDb = async () => {
  if (isConnected) return;

  try {
    const db = await mongoose.connect(process.env.MONGO_URL);
    isConnected = db.connections[0].readyState;
    console.log("Database connected");
  } catch (err) {
    console.error("DB connection failed", err);
  }
};

module.exports = connectDb;
