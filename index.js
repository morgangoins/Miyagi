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

// Ensure table exists
pool.query(`
  CREATE TABLE IF NOT EXISTS login_history (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).catch(err => console.error('Error creating table:', err));

const app = express();
const PORT = process.env.PORT || 8000;

// Configure session before passport
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret',
  resave: true,
  saveUninitialized: true,
  cookie: { 
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
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
    callbackURL: process.env.CALLBACK_URL || "http://localhost:8000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('Google profile:', JSON.stringify(profile));
      const user = {
        id: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        firstName: profile.name.givenName,
        photos: profile.photos
      };
      await pool.query(
        'INSERT INTO login_history (user_id, email) VALUES ($1, $2)',
        [user.id, user.email]
      );
      return done(null, user);
    } catch (err) {
      console.error('Error in Google Strategy:', err);
      return done(err, null);
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
    if (!req.user) {
      console.error('No user data after Google authentication');
      return res.redirect('/');
    }
    console.log('Authentication successful, user:', req.user.id);
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.redirect('/');
      }
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
  console.log('Session:', req.session);
  console.log('User:', req.user);
  
  if (!req.isAuthenticated() || !req.user) {
    console.error('Authentication failed');
    return res.redirect('/');
  }

  try {
    // More detailed error checking
    if (!req.user) {
      console.error('No user object');
      return res.status(500).send('No user data available');
    }
    
    if (!req.user.id) {
      console.error('No user ID:', req.user);
      return res.status(500).send('Missing user ID');
    }

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
