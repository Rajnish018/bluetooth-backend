import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import {
  generateAccessToken,
  generateRefreshToken
} from "../utils/token.utils.js";


/* ==========================================================
   REGISTER
========================================================== */

export const register = async (req, res) => {
  try {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = refreshToken;
    await user.save();

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });

  } catch (error) {

    console.error("Register Error:", error);

    res.status(500).json({
      success: false,
      message: "Internal Server Error"
    });

  }
};



/* ==========================================================
   LOGIN
========================================================== */

export const login = async (req, res) => {

  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    /* =============================
       Generate Tokens
    ============================= */

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    /* =============================
       Save Refresh Token
    ============================= */

    user.refreshToken = refreshToken;
    await user.save();

    /* =============================
       Response
    ============================= */

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      tokens: {
        accessToken,
        refreshToken
      }
    });

  } catch (error) {

    console.error("Login Error:", error);

    res.status(500).json({
      success: false,
      message: "Internal Server Error"
    });

  }
};


export const logout = async (req, res) => {

  try {

    await User.findByIdAndUpdate(req.userId, {
      refreshToken: null
    });

    res.json({
      success: true,
      message: "Logout successful"
    });

  } catch (error) {

    res.status(500).json({
      success: false,
      message: "Internal Server Error"
    });

  }

};

export const refreshToken = async (req, res) => {
  try {

    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Refresh token required"
      });
    }

    /* =============================
       Verify Token
    ============================= */

    let decoded;

    try {
      decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
    } catch (error) {
      return res.status(403).json({
        success: false,
        message: "Invalid refresh token"
      });
    }

    /* =============================
       Find User
    ============================= */

    const user = await User.findById(decoded.userId);

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({
        success: false,
        message: "Refresh token not valid"
      });
    }

    /* =============================
       Generate New Tokens
    ============================= */

    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    /* =============================
       Token Rotation
    ============================= */

    user.refreshToken = newRefreshToken;
    await user.save();

    /* =============================
       Response
    ============================= */

    res.json({
      success: true,
      tokens: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    });

  } catch (error) {

    console.error("Refresh Token Error:", error);

    res.status(500).json({
      success: false,
      message: "Internal Server Error"
    });

  }
};



/* ==========================================================
   GET PROFILE
========================================================== */

// auth.controller.js
export const getProfile = async (req, res) => {
  try {
    // Change req.user.id to req.userId to match your current middleware
    const user = await User.findById(req.userId).select("-password"); 

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
};