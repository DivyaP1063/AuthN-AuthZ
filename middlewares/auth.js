const jwt = require("jsonwebtoken");
require("dotenv").config();

// Middleware to authenticate using JWT
exports.auth = (req, res, next) => {
    try {
        // Extract JWT token
        const token = req.cookies || req.body.token || req.header("Authorization").replace("Bearer","");

        if (!token || token==undefined) {
            return res.status(401).json({
                success: false,
                message: 'Token missing'
            });
        }

        try {
            // Verify JWT token
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode; // Attach decoded token to request object
        } catch (error) {
            return res.status(401).json({
                success: false,
                message: 'Token is invalid'
            });
        }

        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Something went wrong while verifying the token'
        });
    }
};

// Middleware to check if the user is a student
exports.isStudent = (req, res, next) => {
    try {
        if (req.user.role !== "Student") {
            return res.status(403).json({
                success: false,
                message: 'This is a protected route for Students'
            });
        }
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'User role is not matching'
        });
    }
};

// Middleware to check if the user is an admin
exports.isAdmin = (req, res, next) => {
    try {
        if (req.user.role !== "Admin") {
            return res.status(403).json({
                success: false,
                message: 'This is a protected route for Admin'
            });
        }
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'User role is not matching'
        });
    }
};
