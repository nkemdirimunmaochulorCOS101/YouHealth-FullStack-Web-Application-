const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require("bcrypt");
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const session = require("express-session");
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");



const app = express();
module.exports = app;
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000; // ⚡ changed to 5000 so frontend can run on 3000
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
FRONTEND_URL="https://wonderful-tiramisu-939d02.netlify.app"

app.use(cors({
  origin: "https://wonderful-tiramisu-939d02.netlify.app", // your Netlify link
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));


const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST, // e.g., smtp.gmail.com
  port: Number(process.env.EMAIL_PORT) || 587,
  secure: false, // true for 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware
app.use(cors());
app.use(express.json());

// ✅ Session & Passport setup
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret-session",
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// ✅ Google OAuth strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails[0].value;

    // Look for existing user
    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      // Create new user if doesn't exist
      user = await prisma.user.create({
        data: {
          firstName: profile.name.givenName || "Google",
          lastName: profile.name.familyName || "User",
          email,
          username: email.split("@")[0],
          password: crypto.randomBytes(16).toString("hex"), // random password
          role: "PATIENT",
        }
      });
    }

    done(null, user); // pass DB user
  } catch (err) {
    done(err, null);
  }
}));


// Google Auth Routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: `${FRONTEND_URL}/Loginpage.html` }),
  async (req, res) => {
    const user = req.user;

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Redirect to frontend with token
    const safeUser = { id: user.id, email: user.email, role: user.role };
    res.redirect(
      `${FRONTEND_URL}/Healthdashboard.html?token=${token}&user=${encodeURIComponent(
        JSON.stringify(safeUser)
      )}`
    );
  }
);




// ========================
// Auth Middleware
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Authentication token required." });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token." });

    // normalize userId field
    req.user = {
      userId: decoded.userId || decoded.id,
      email: decoded.email,
      role: decoded.role,
    };

    next();
  });
};


function generateToken(userId) {
  return jwt.sign(
    { id: userId }, 
    process.env.JWT_SECRET || "default_secret",
    { expiresIn: "1d" }
  );
}

// Get all users (admin only)
app.get("/api/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({ error: "Unauthorized" });
  }
  const users = await prisma.user.findMany({
    select: { id: true, firstName: true, lastName: true, email: true, role: true }
  });
  res.json(users);
});



// ========================
// Test Routes
// ========================
app.get('/', (req, res) => {
  res.status(200).send('YouHealth backend is running!');
});

app.get('/api/test-db', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.status(200).json({ message: 'Database connection successful!' });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ error: 'Database connection failed.', details: error.message });
  }
});

// ========================
// Auth Routes
// ========================
app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, username, email, password, role, specialty } = req.body;

  // 1️⃣ Validate input
  if (!firstName || !lastName || !username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // 2️⃣ Check if username already exists
    const existingUser = await prisma.user.findUnique({
      where: { username }
    });
    if (existingUser) {
      return res.status(400).json({ error: "Username already taken" });
    }

    // 3️⃣ Check if email already exists
    const existingEmail = await prisma.user.findUnique({
      where: { email }
    });
    if (existingEmail) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // 4️⃣ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5️⃣ Create user
    const user = await prisma.user.create({
      data: {
        firstName,
        lastName,
        username,
        email,
        password: hashedPassword,
        role,
        specialty
      }
    });

    // 6️⃣ Generate JWT token
    const token = generateToken(user.id); // make sure generateToken() is defined

    return res.status(201).json({
      message: "Registration successful",
      user,
      token
    });

  } catch (err) {
    // Handle Prisma unique constraint error safely
    if (err.code === "P2002") {
      return res.status(400).json({ error: "Username or email already exists" });
    }

    console.error("Registration error:", err);
    return res.status(500).json({ error: "Server error during registration" });
  }
});

app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    console.log("Decoded user:", req.user); // ✅ debug

    const user = await prisma.user.findUnique({
      where: { id: req.user.userId }, // ✅ requires userId in token
      select: {
        id: true,
        fullName: true,
        email: true,
        username: true,
        specialty: true,
        profileImage: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ error: "Server error loading profile" });
  }
});



app.post("/api/users/:id/details", async (req, res) => {
  const { qualifications, phonenumber, address, about, availabletime } = req.body;
  const userId = req.params.id;

  try {
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { qualifications, phonenumber, address, about, availabletime }
    });
    res.json({ user: updatedUser, message: "Sign Up Successful! Redirecting" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save user details" });
  }
});


app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: "Login successful!",
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        specialty: user.specialty,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

const multer = require("multer");

const upload = multer({ storage: multer.memoryStorage() });

app.put("/api/user/update", authenticateToken, upload.single("profileImage"), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { fullName, email, username, specialty, password } = req.body;

    // Split fullName into firstName and lastName
    let firstName = "", lastName = "";
    if (fullName) {
      const parts = fullName.trim().split(" ");
      firstName = parts[0];
      lastName = parts.slice(1).join(" ");
    }

    const dataToUpdate = { firstName, lastName, specialty };

    if (username) dataToUpdate.username = username;
    if (email) dataToUpdate.email = email;
    if (password) dataToUpdate.password = await bcrypt.hash(password, 10);
    if (req.file) dataToUpdate.profileImage = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: dataToUpdate,
    });

    updatedUser.fullName = `${updatedUser.firstName || ""} ${updatedUser.lastName || ""}`.trim();
    res.json({ message: "✅ Profile updated successfully!", user: updatedUser });
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ error: "Server error updating profile" });
  }
});


app.get("/api/user/me", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId || req.user.id; // fallback for Google OAuth tokens
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        username: true,
        specialty: true,
        profileImage: true,
      }
    });

    if (!user) return res.status(404).json({ error: "User not found" });

    // compute fullName
    user.fullName = `${user.firstName || ""} ${user.lastName || ""}`.trim();

    res.json(user);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ error: "Server error fetching profile" });
  }
});




// ========================
// Appointments
// ========================
app.get("/appointments", authenticateToken, async (req, res) => {
  try {
    let where = {};

    if (req.user.role === "PATIENT") {
      where = { patientId: req.user.userId };
    } else if (req.user.role === "PRACTITIONER") {
      where = { doctorId: req.user.userId };
    }

    const appts = await prisma.appointment.findMany({
      where,
      orderBy: { dateTime: "desc" },
      include: {
        doctor: { select: { id: true, firstName: true, lastName: true, specialty: true } },
        patient: { select: { id: true, firstName: true, lastName: true } },
      },
    });

    res.json(appts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error fetching appointments" });
  }
});

app.post("/appointments", authenticateToken, async (req, res) => {
  try {
    const { doctorId, date, time, type, status } = req.body;

    if (req.user.role !== "PATIENT") {
      return res.status(403).json({ error: "Only patients can create appointments" });
    }

    if (!doctorId || !date || !time) {
      return res.status(400).json({ error: "doctorId, date and time are required" });
    }

    const dateTime = new Date(`${date}T${time}:00Z`);
    if (isNaN(dateTime.getTime())) {
      return res.status(400).json({ error: "Invalid date or time format" });
    }

    const typeMap = {
      "in-person": "IN_PERSON",
      "telehealth": "TELEHEALTH"
    };
    const mappedType = typeMap[type?.toLowerCase()] || "IN_PERSON";

    const statusMap = {
      "confirmed": "CONFIRMED",
      "pending": "PENDING",
      "cancelled": "CANCELLED"
    };
    const mappedStatus = statusMap[status?.toLowerCase()] || "CONFIRMED";

    const practitioner = await prisma.user.findUnique({ where: { id: doctorId } });
    if (!practitioner) {
      return res.status(400).json({ error: "Practitioner not found (invalid doctorId)" });
    }

    const patientId = req.user.userId;

    const appointment = await prisma.appointment.create({
      data: {
        doctorId,
        patientId,
        dateTime,
        type: mappedType,
        status: mappedStatus
      },
      include: {
        doctor: { select: { id: true, firstName: true, lastName: true, specialty: true } },
        patient: { select: { id: true, firstName: true, lastName: true } }
      }
    });

    return res.json(appointment);
  } catch (err) {
    console.error("Error creating appointment:", err);
    if (err.code === "P2003") {
      return res.status(400).json({ error: "Foreign key constraint failed — check doctorId exists." });
    }
    return res.status(500).json({ error: "Server error creating appointment", details: err.message });
  }
});

// GET all appointments for a specific doctor
app.get("/practitioner/:doctorId", async (req, res) => {
  try {
    const { doctorId } = req.params;

    // Find appointments for the doctor
    const appointments = await Appointment.find({ doctorId })
      .populate("patient", "firstName lastName email") // populate patient info if using references
      .sort({ dateTime: 1 });

    res.json(appointments);
  } catch (err) {
    console.error("Error fetching appointments:", err);
    res.status(500).json({ error: "Failed to fetch appointments" });
  }
});


app.get("/appointments/practitioner/:id", async (req, res) => {
  const doctorId = req.params.id; // keep as string
  try {
    const appointments = await prisma.appointment.findMany({
      where: { doctorId },
      include: { patient: true }
    });
    res.json(appointments);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch appointments" });
  }
});


app.put("/appointments/:id/cancel", authenticateToken, async (req, res) => {
  try {
    const appointmentId = req.params.id; // ✅ keep as string (UUID)

    const updated = await prisma.appointment.update({
      where: { id: appointmentId },
      data: { status: "CANCELLED" } // ✅ must match your AppointmentStatus enum
    });

    res.json({ message: "Appointment cancelled successfully", updated });
  } catch (err) {
    console.error("Cancel error:", err);
    res.status(500).json({ error: "Failed to cancel appointment" });
  }
});




// ========================
// Practitioners
// ========================
app.get("/practitioners", async (req, res) => {
  try {
    const practitioners = await prisma.user.findMany({
      where: {
        role: "PRACTITIONER"
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        role: true,
        specialty: true,
        phonenumber: true,
        about: true,
        qualifications: true,
        availabletime: true
      }
    });

    res.json(practitioners);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch practitioners" });
  }
});




// ========================
// Medications
// ========================
app.get("/medications", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const medications = await prisma.medication.findMany({
      where: { patientId: userId },
      orderBy: { createdAt: "desc" },
    });

    res.json(medications);
  } catch (error) {
    console.error("Error fetching medications:", error);
    res.status(500).json({ error: "Failed to fetch medications" });
  }
});

// ========================
// Patients endpoints
// ========================

// GET /patients
// Returns list of patient records with computed lastVisit and nextAppointment (from appointments)
app.get("/patients", authenticateToken, async (req, res) => {
  try {
    const patients = await prisma.user.findMany({
      where: { role: "PATIENT" },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        username: true,
        createdAt: true,
      },
    });
    res.json(patients);
  } catch (err) {
    console.error("Error fetching patients:", err);
    res.status(500).json({ error: "Failed to fetch patients" });
  }
});

// Add near other routes in server.js
app.get("/patients/search", authenticateToken, async (req, res) => {
  const name = req.query.name || "";
  if (!name) return res.status(400).json({ error: "Name query required" });

  try {
    const patients = await prisma.user.findMany({
      where: {
        role: "PATIENT",
        OR: [
          { firstName: { contains: name, mode: "insensitive" } },
          { lastName: { contains: name, mode: "insensitive" } },
          { username: { contains: name, mode: "insensitive" } }
        ]
      },
      select: { id: true, firstName: true, lastName: true, email: true }
    });
    res.json(patients);
  } catch (err) {
    console.error("Error searching patients:", err);
    res.status(500).json({ error: "Search failed" });
  }
});



// POST /patients
// Create a new patient record (practitioner/admin only).
// NOTE: this creates a minimal user with a generated email + hashed password to satisfy schemas requiring those fields.
// If your schema allows creating patients without email/password, you can simplify this.
// ================= Add Patient =================
app.post("/patients", authenticateToken, async (req, res) => {
  try {
    // Only allow PRACTITIONER or ADMIN to add patients
    if (req.user.role !== "PRACTITIONER" && req.user.role !== "ADMIN") {
      return res.status(403).json({ error: "Unauthorized: Only practitioners or admins can add patients" });
    }

    const { firstName, lastName, username, email, password } = req.body;

    // Validate required fields
    if (!firstName || !lastName || !username || !email || !password) {
      return res.status(400).json({ error: "All fields (firstName, lastName, username, email, password) are required" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const patient = await prisma.user.create({
      data: {
        firstName,
        lastName,
        username,
        email,
        password: hashedPassword,
        role: "PATIENT", // force role
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        username: true,
        role: true,
      },
    });

    res.status(201).json(patient);
  } catch (err) {
    console.error("Error adding patient:", err);
    if (err.code === "P2002") {
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Server error while adding patient", details: err.message });
  }
});


app.post("/medications", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    if (!userId) {
      return res.status(401).json({ error: "User ID missing from token" });
    }

    const medication = await prisma.medication.create({
      data: {
        patientId: userId,
        name: req.body.name,
        dosage: req.body.dosage,
        frequency: req.body.frequency,
        instructions: req.body.instructions,
        status: req.body.status || "ACTIVE",
      },
    });

    res.json(medication);
  } catch (error) {
    console.error("Error creating medication:", error);
    res.status(500).json({ error: "Failed to create medication" });
  }
});

/// DELETE a medication by ID
app.delete("/medications/:id", authenticateToken, async (req, res) => {
  try {
    const medId = req.params.id; // keep as string

    // Check if medication exists
    const medication = await prisma.medication.findUnique({
      where: { id: medId },
    });

    if (!medication) {
      return res.status(404).json({ error: "Medication not found" });
    }

    // Delete medication
    await prisma.medication.delete({ where: { id: medId } });

    res.json({ message: "Medication deleted successfully" });
  } catch (err) {
    console.error("Delete medication error:", err);
    res.status(500).json({ error: "Failed to delete medication" });
  }
});



// ========================
// Vitals
// ========================
app.get('/api/vitals', authenticateToken, async (req, res) => {
  try {
    const vitals = await prisma.healthVitals.findMany({
      where: { patientId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    res.status(200).json(vitals);
  } catch (error) {
    console.error('Error fetching vitals:', error);
    res.status(500).json({ error: 'Failed to fetch vitals.' });
  }
});

app.post('/api/vitals', authenticateToken, async (req, res) => {
  try {
    const { bloodPressure, oxygenSaturation } = req.body;
    const newVitals = await prisma.healthVitals.create({
      data: {
        bloodPressure,
        oxygenSaturation,
        patient: { connect: { id: req.user.userId } }
      }
    });
    res.status(201).json(newVitals);
  } catch (error) {
    console.error('Error adding vitals:', error);
    res.status(500).json({ error: 'Failed to add vitals.', details: error.message });
  }
});

// Delete current user account
app.delete("/api/auth/delete-account", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Delete related records first if you have foreign keys
    await prisma.appointment.deleteMany({ where: { OR: [{ patientId: userId }, { doctorId: userId }] } });
    await prisma.medication.deleteMany({ where: { patientId: userId } });
    await prisma.healthVitals.deleteMany({ where: { patientId: userId } });

    // Finally delete the user
    await prisma.user.delete({ where: { id: userId } });

    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// Forgot Password
const sendEmail = require("../src/services/email"); // adjust path

// Forgot Password Example (TODO: Save resetToken + expiry in DB properly)
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken: token,
        resetTokenExpiry: new Date(Date.now() + 15 * 60 * 1000), // 15 mins
      },
    });

    // Redirect link points to Netlify login page
    const resetLink = `${FRONTEND_URL}/Loginpage.html?resetToken=${token}`;
    res.json({ message: "Password reset link generated", resetLink });
  } catch (err) {
    res.status(500).json({ error: "Something went wrong" });
  }
});

// Reset Password
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await prisma.user.findFirst({
      where: { resetToken: token, resetTokenExpiry: { gt: new Date() } },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired token." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    res.json({ message: "Password reset successfully! You can now log in." });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Server error while resetting password." });
  }
});


// Node/Express example
app.get("/patients/practitioner", authenticateToken, async (req, res) => {
  const practitionerId = req.user.id; // decoded from JWT
  const patients = await db.patient.find({ practitionerId });
  res.json(patients);
});


// ========================
// Start server
// ========================
app.listen(PORT, () => {
  console.log(`✅ Server is running at http://localhost:${PORT}`);
});