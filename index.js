const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
require('dotenv').config();
const expressSession = require('express-session');

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
  (accessToken, refreshToken, profile, done) => {
    // Here you would typically find or create a user in your database
    return done(null, profile);
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
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.send(`<h1>Hello, ${req.user.displayName}</h1><a href="/logout">Logout</a>`);
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
