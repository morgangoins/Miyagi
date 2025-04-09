const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
require('dotenv').config();
const expressSession = require('express-session');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const app = express();
const PORT = process.env.PORT || 8000;

// Monkey patch for compatibility
const originalSessionMethod = expressSession;
const compatibilityFix = function(options) {
  const instance = originalSessionMethod(options);
  
  // Add regenerate and save methods if they don't exist
  const patchedInstance = (req, res, next) => {
    const originalSession = req.session;
    
    instance(req, res, () => {
      if (originalSession && typeof originalSession.regenerate !== 'function') {
        originalSession.regenerate = function(cb) {
          if (typeof cb === 'function') {
            cb();
          }
        };
      }
      
      if (originalSession && typeof originalSession.save !== 'function') {
        originalSession.save = function(cb) {
          if (typeof cb === 'function') {
            cb();
          }
        };
      }
      
      next();
    });
  };
  
  return patchedInstance;
};

// Use the patched version
app.use(compatibilityFix({
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
  passport.authenticate('google', { 
    failureRedirect: '/',
    successRedirect: '/profile'
  })
);

// Protected route
app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  
  try {
    const result = await pool.query(
      'SELECT * FROM login_history WHERE user_id = $1 ORDER BY login_time DESC LIMIT 5',
      [req.user.id]
    );
    
    const loginHistory = result.rows.map(row => {
      return `${new Date(row.login_time).toLocaleString()}`;
    }).join('<br>');
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            margin: 0;
            font-family: Arial, sans-serif;
            padding: 20px;
          }
          .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            border-bottom: 1px solid #eee;
          }
          .logo {
            font-size: 48px;
            color: #333;
            text-decoration: none;
          }
          .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
            position: fixed;
            bottom: 20px;
            left: 20px;
          }
          .profile-img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
          }
          .logout {
            position: fixed;
            bottom: 20px;
            right: 20px;
          }
          .content {
            margin-top: 40px;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <a href="/" class="logo">Miyagi</a>
        </div>
        <div class="content">
          <h2>Your Recent Logins:</h2>
          <p>${loginHistory}</p>
        </div>
        <div class="user-info">
          <img src="${req.user.photos[0].value}" class="profile-img" alt="Profile">
          <span>${req.user.name.givenName}</span>
        </div>
        <a href="/logout" class="logout">Logout</a>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('Error fetching login history:', err);
    res.send(`<h1>Hello, ${req.user.displayName}</h1><a href="/logout">Logout</a>`);
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
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
