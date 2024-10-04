const express = require("express");
const router = express.Router();

const { signup,login} = require("../Controllers/Auth");
const {auth,isStudent,isAdmin} = require("../middlewares/auth");
router.post("/login",login);
router.post("/signup",signup);

//Protected route for Tesing
router.get("/test",auth,(req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected route Testing route'
    })
})
//Protected routes
router.get("/student", auth,isStudent,(req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected route for Students'
    })
})

router.get("/admin", auth,isAdmin,(req,res)=>{
    res.json({
        success:true,
        message:'Welcome to the Protected route for Admin'
    })
})

module.exports = router;