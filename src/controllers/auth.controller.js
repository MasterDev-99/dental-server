// controllers/auth.controller.js
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;
const admin = require("../utils/firebaseAdmin");
const prisma = require("../prisma/client");

const bcrypt = require("bcrypt");
const SALT_ROUNDS = 10;

// 🎯 Issue JWT
function generateToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "24h" });
}

// 🔐 Google Login – Check if user exists
exports.googleLogin = async (req, res) => {
  const { idToken } = req.body;

  // Validate input
  if (!idToken) {
    return res.status(400).json({
      success: false,
      message: "idToken is required",
    });
  }

  try {
    // Verify Firebase token
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, email_verified } = decoded;

    // Check if email is verified by Google
    if (!email_verified) {
      return res.status(403).json({
        success: false,
        message: "Email not verified by Google",
      });
    }

    // Check if user exists in database
    let user = await prisma.user.findUnique({ where: { email } });

    const isNewUser = !user;

    // Create user if doesn't exist (optional - depends on your flow)
    if (!user) {
      // You might want to create the user automatically
      // Or redirect to a signup completion page
      user = await prisma.user.create({
        data: {
          email,
          fullName: name || email.split('@')[0],
          profileImage: picture || null,
          role: 'PATIENT', // Default role or get from frontend
          isActive: true,
          emailVerified: true,
        },
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        role: user.role,
        email: user.email 
      }, 
      JWT_SECRET, 
      { 
        expiresIn: '24h' 
      }
    );

    // Set HTTP-only cookie (optional but more secure)
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    // Return response
    return res.status(200).json({
      success: true,
      isNewUser, // Let frontend know if this is a new user
      message: isNewUser ? "User created successfully" : "Login successful",
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        profileImage: user.profileImage,
      },
      token: token, // Still return token for mobile/SPA if needed
    });

  } catch (error) {
    console.error("Google login error:", error);

    // Handle specific Firebase errors
    if (error.code === 'auth/id-token-expired') {
      return res.status(401).json({
        success: false,
        message: "Google token has expired",
      });
    }

    if (error.code === 'auth/argument-error') {
      return res.status(400).json({
        success: false,
        message: "Invalid Google token format",
      });
    }

    // Generic error
    return res.status(500).json({
      success: false,
      message: "Authentication failed",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

// ✅ Google Registration – Create new user after Google login
exports.completeGoogleRegistration = async (req, res) => {
  const { idToken, role } = req.body;

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name } = decoded;

    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (existingUser) {
      return res.status(400).json({ success: false, result: "User already exists" });
    }

    const newUser = await prisma.user.create({
      data: { email, name, role },
    });

    const token = generateToken(newUser);
    return res.status(201).json({ success: true, result: { token, user: newUser } });
  } catch (error) {
    console.error("Complete Google registration error:", error);
    return res.status(500).json({ success: false, result: "Internal server error" });
  }
};

// 🧾 Register – Manual form registration
exports.register = async (req, res) => {
  const { role, name, email, password } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ success: false, result: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = await prisma.user.create({
      data: {
        email,
        name,
        role,
        password: hashedPassword,
      },
    });

    return res.status(201).json({ success: true, result: newUser });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ success: false, result: "Internal server error" });
  }
};

// 🔐 Email/password Login – if you still need it
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !user.password) {
      return res.status(201).json({ success: false, result: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(201).json({ success: false, result: "Invalid email or password" });
    }

    const token = generateToken(user);
    return res.status(200).json({ success: true, result: { token, user } });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, result: "Internal server error" });
  }
};
