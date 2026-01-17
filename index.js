require("dotenv").config();
const express=require("express");
const cors=require("cors");
const jwt=require("jsonwebtoken");
const bcrypt=require('bcrypt');
const cookieParser=require("cookie-parser");

const app=express();
const connectDb=require("./DB/Config");
app.use(cors({
    origin:"http://localhost:5173",
    credentials:true,
}));
app.use(express.json());
app.use(cookieParser());
const User=require("./DB/UserSchema");
connectDb();
const authMiddleware=(req,resp,next)=>{
    const token=req.cookies.token;
    if(!token){
        return resp.status(401).json({message:"Unauthorized"});
    }
   try{
     const decoded=jwt.verify(token,process.env.JWT_SECRET);
    req.user=decoded;
    next();
   }catch(err){
    return resp.status(401).json({message:"Invalid token"});
   }
}



// SingUp Api

app.post("/signup",async(req,resp)=>{
    try{
        const {name,email,password,number,role}=req.body ;
        const userExist= await User.findOne({email});
        if (userExist){return resp.status(400).json({message:"User already registerd"})};

        const hashedPassword= await bcrypt.hash(password,10);
        const newUser= new User({name,email,number,password:hashedPassword,role});
        await newUser.save();
        const token=jwt.sign({id:newUser._id,role:newUser.role},process.env.JWT_SECRET,{expiresIn:"1h"});
         resp.cookie("token",token,{httpOnly:true,secure:false ,sameSite:"strict"});


        return resp.status(201).json({message:"user created",user:{id:newUser._id,name:newUser.name,email:newUser.email,number:newUser.number,role:newUser.role},token} );


       
}   catch(err){
        console.log("Error in SingUp Api",err);
        return resp.status(500).json({message:"Internal server error"})
}}
);

//Login Api
app.post("/login",async(req,resp)=>{
    try{
        const {email,password}=req.body;
        const findUser=await User.findOne({email});
        if(!findUser)
        {return resp.status(400).json({message:"User not found"})};
        const isPasswordMatch=await bcrypt.compare(password,findUser.password);
        if(!isPasswordMatch){
            return resp.status(401).json({message:"Invalid credentials"});
        }
        const token=jwt.sign({id:findUser._id,role:findUser.role},process.env.JWT_SECRET,{expiresIn:"1h"});
        resp.cookie("token",token,{httpOnly:true,secure:false ,sameSite:"strict"});
        return resp.status(200).json({message:"Login successful",user:{id:findUser._id,name:findUser.name,email:findUser.email,number:findUser.number,role:findUser.role},token});
    }catch(err){
        console.log("Error in Login Api",err);
        return resp.status(500).json({message:"Internal server error"})
    }
})

// check user is already logged in or not
app.get("/checkAuth",authMiddleware,async (req,resp)=>{
   
    try{
        const user=await User.findById(req.user.id).select("role");
        if(!user){
            return resp.status(401  ).json({message:"User not found"});
        }   
        return resp.status(200).json({message:"user logged in",role:user.role});
    }catch(err){
        console.log("Error in checkAuth Api",err);
        return resp.status(500).json({message:"Internal server error"})
    }

})
// Logout Api
app.post('/logout',async(req,resp)=>{
    try{
        const response= resp.clearCookie("token",{httpOnly:true,secure:false ,sameSite:"strict"});
        return resp.status(200).json({message:"Logout successful"});    
    } catch(err){
        console.log("Error in Logout Api",err);
        return resp.status(500).json({message:"Internal server error"}) 
}})



const PORT=process.env.PORT || 5000;
app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`,"Mongo URI:")})
