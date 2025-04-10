const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
const fs = require('fs');
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
    callbackURL: process.env.CALLBACK_URL || "https://" + process.env.REPL_SLUG + "." + process.env.REPL_OWNER + ".repl.co/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('Google profile received:', profile.id);
      console.log('Full profile:', JSON.stringify(profile, null, 2));
      const user = {
        id: profile.id,
        email: profile.emails?.[0]?.value || '',
        displayName: profile.displayName || '',
        photo: profile.photos?.[0]?.value || '',
        name: profile.name || {}
      };
      
      console.log('Processed user data:', user);
      
      await pool.query(
        'INSERT INTO login_history (user_id, email) VALUES ($1, $2)',
        [user.id, user.email]
      );
      
      return done(null, user);
    } catch (err) {
      console.error('Error in Google Strategy:', err);
      return done(null, false, { message: 'Failed to process user profile' });
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
    successRedirect: '/profile',
    failureFlash: true
  })
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

    // Ensure the data matches exactly what the template expects
    const userData = {
      photoUrl: req.user.photo || 'https://www.gravatar.com/avatar/?d=mp',
      firstName: req.user.displayName || 'User',
      loginHistory: loginHistory || 'No login history available'
    };

    // Read and send the template file directly
    res.sendFile(path.join(__dirname, 'public', 'profile.html'), {}, (err) => {
      if (err) {
        console.error('Error sending profile.html:', err);
        res.status(500).send('Error loading profile page');
        return;
      }
    });
  } catch (err) {
    console.error('Error in profile route:', err);
    console.error('Current user data:', JSON.stringify(req.user, null, 2));
    res.status(500).send('Error loading profile');
  }
});

// Updated Logout route compatible with newer Passport versions
// API endpoint to get user data
app.get('/api/user-data', ensureAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM login_history WHERE user_id = $1 ORDER BY login_time DESC LIMIT 5',
      [req.user.id]
    );
    
    const loginHistory = result.rows.map(row => {
      return `${new Date(row.login_time).toLocaleString()}`;
    }).join('<br>');

    const userData = {
      photoUrl: req.user.photo || 'https://www.gravatar.com/avatar/?d=mp',
      firstName: req.user.displayName || 'User',
      loginHistory: loginHistory || 'No login history available'
    };

    res.json(userData);
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

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
