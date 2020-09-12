const mongoose = require("mongoose");
const config = require("config");
const db = config.get("MongoURI");

const connectDB = async () => {
  try {
    await mongoose.connect(db, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
    });

    console.log("MongoDB Connected...");
  } catch (err) {
    console.error(err);
    //If a error happens it will close the application
    process.exit(1);
  }
};

module.exports = connectDB;
