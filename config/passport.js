// Import các thư viện cần thiết
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user.js'); 
const bcrypt = require('bcryptjs');


// Đăng ký strategy với tên 'local.signin'
passport.use('local.signin', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return done(null, false, {message: 'User not found.'});
        }
       const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Incorrect password' });
        }
// Gọi req.login để tạo session khi đăng nhập thành công
        req.login(user, (err) => {
            if (err) return done(err);
            return done(null, user);
        });

    } catch (error) {
        return done(error);
    }
      
}));



// Serialize và Deserialize User cho session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
  }  
});

module.exports = passport;
