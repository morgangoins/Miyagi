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

    // Read and send the profile.html file
    let html = await fs.promises.readFile(path.join(__dirname, 'public', 'profile.html'), 'utf8');
    
    // Replace the placeholder with actual user data
    const userData = {
      photoUrl: req.user.photos[0].value,
      firstName: req.user.name.givenName,
      loginHistory: loginHistory
    };
    
    html = html.replace('{USERDATA}', JSON.stringify(userData));
    res.send(html);
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
