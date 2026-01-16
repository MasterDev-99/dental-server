// src/app.js
require("dotenv").config();
const express = require("express");
const cors = require("cors"); // Make sure to install: npm install cors

const authenticate = require("./middleware/authenticate");
const authRoutes = require("./routes/auth.routes");
const usersRoutes = require("./routes/users.routes");
const patientRoutes = require("./routes/patient.routes");
const incidentRoutes = require("./routes/incident.routes");
const chatbotRoutes = require("./routes/chatbot.routes");

const app = express();

/**
 * =====================================================
 * 🔥 SIMPLIFIED CORS - Remove duplicate headers
 * =====================================================
 */

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "https://denta-client.vercel.app",
  "https://dental-client.vercel.app"
];

// OPTION 1: Use ONLY the cors package (remove custom middleware)
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      // For now, allow all origins to debug
      return callback(null, true);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// OPTION 2: Or use ONLY custom middleware (comment out the cors() line above)
/*
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});
*/

/**
 * =====================================================
 * Body Parser
 * =====================================================
 */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * =====================================================
 * Routes
 * =====================================================
 */
app.use("/api/auth", authRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/patients", authenticate, patientRoutes);
app.use("/api/incidents", authenticate, incidentRoutes);
app.use("/api/chatbot", authenticate, chatbotRoutes);

/**
 * =====================================================
 * Health & Test Routes
 * =====================================================
 */
app.get("/", (req, res) => {
  res.send("Denta API Running");
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "healthy", 
    timestamp: new Date().toISOString(),
    origin: req.headers.origin
  });
});

// Remove the app.options("*") route - let cors middleware handle it

module.exports = app;