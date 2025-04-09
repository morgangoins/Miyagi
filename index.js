const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const app = express();
const PORT = process.env.PORT || 8000;

// Configure session before passport
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || "http://localhost:3000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      await pool.query(
        'INSERT INTO login_history (user_id, email) VALUES ($1, $2)',
        [profile.id, profile.emails[0].value]
      );
      return done(null, profile);
    } catch (err) {
      console.error('Error logging login:', err);
      return done(null, profile);
    }
  }
));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Auth routes
app.get('/auth/google', 
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    req.session.save(() => {
      res.redirect('/profile');
    });
  }
);

// Middleware to check authentication
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
};

// Protected route
app.get('/profile', ensureAuthenticated, async (req, res) => {
  
  try {
    const result = await pool.query(
      'SELECT * FROM login_history WHERE user_id = $1 ORDER BY login_time DESC LIMIT 5',
      [req.user.id]
    );
    
    const loginHistory = result.rows.map(row => {
      return `${new Date(row.login_time).toLocaleString()}`;
    }).join('<br>');

    const userData = {
      photoUrl: req.user.photos[0].value,
      firstName: req.user.name.givenName,
      loginHistory: loginHistory
    };

    res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Miyagi - Profile</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Arial, sans-serif;
      position: relative;
      padding: 0;
    }
    .header {
      padding: 20px;
      border-bottom: 1px solid #eee;
    }
    .logo {
      font-size: 48px;
      color: #333;
      text-decoration: none;
      font-family: Arial, sans-serif;
    }
    .user-info {
      display: flex;
      align-items: center;
      gap: 12px;
      position: fixed;
      bottom: 20px;
      left: 20px;
      background: white;
      padding: 10px;
      border-radius: 25px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .profile-img {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      border: 2px solid #eee;
    }
    .user-name {
      font-size: 16px;
      color: #333;
    }
    .logout {
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 8px 16px;
      background: #f8f9fa;
      border: 1px solid #dadce0;
      border-radius: 4px;
      color: #3c4043;
      text-decoration: none;
    }
    .logout:hover {
      background: #f1f3f4;
    }
    .content {
      padding: 40px;
    }
  </style>
</head>
<body>
  <div class="header">
    <a href="/" class="logo">Miyagi</a>
  </div>
  <div class="content">
    <h2>Your Recent Logins:</h2>
    <p id="loginHistory">${userData.loginHistory}</p>
  </div>
  <div class="user-info">
    <img src="${userData.photoUrl}" class="profile-img" alt="Profile">
    <span class="user-name">${userData.firstName}</span>
  </div>
  <a href="/logout" class="logout">Sign out</a>
</body>
</html>
    `);
  } catch (err) {
    console.error('Error in profile route:', err);
    res.status(500).send('Error loading profile');
  }
});

// Updated Logout route compatible with newer Passport versions
app.get('/logout', function(req, res, next) {
  // Use req.logout with a callback function
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
