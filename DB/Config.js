const mongoose = require('mongoose');
const connectDb=async()=>{
    try{
         await mongoose.connect(process.env.MONGO_URL);
        console.log("Database connected successfully");
    }catch(err){
        console.log("Database connection failed", err);
        process.exit(1);
    }
}
module.exports=connectDb;