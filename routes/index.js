const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../models/user.js');
const csrf = require('csurf');
const csrfProtection = csrf();

// Sử dụng bảo vệ CSRF cho tất cả các route trong router này
router.use(csrfProtection);

// Middleware kiểm tra nếu đã đăng nhập
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Middleware kiểm tra nếu chưa đăng nhập
function isNotLoggedIn(req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    res.redirect('/check-type');
}
// Sửa lỗi ở route trang chủ '/'
router.get('/', (req, res) => {
    res.redirect('/login');
});

router.post('/login', (req, res) => {
    console.log('Received POST request:', req.body);
    res.send('POST request processed successfully!');
});

// Trang đăng nhập (login)
router.get('/login', isNotLoggedIn, (req, res) => {
    const messages = req.flash('error');
    res.render('login', {
        title: 'Sign In',
        csrfToken: req.csrfToken(),
        messages: messages,
        hasErrors: messages.length > 0
    });
});

// Xử lý đăng nhập
router.post('/login', 
    passport.authenticate('local.signin', {
        failureRedirect: '/login',
        failureFlash: true,
    }),
    (req, res) => {
        // Đảm bảo req.login hoạt động chính xác
        req.login(req.user, (err) => {
            if (err) {
                console.error('Lỗi đăng nhập:', err);
                return res.redirect('/login');
            }
            res.redirect('/check-type');
        });
    }
);
// Xử lý đăng xuất
router.get('/logout', isLoggedIn, (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
req.session.destroy(() => {
        res.redirect('/');
    });
});
});
// Trang kiểm tra loại người dùng và điều hướng
router.get('/check-type', isLoggedIn, (req, res) => {
    req.session.user = req.user;
    const userType = req.user.type;
    if (userType === "project_manager" || userType === "accounts_manager") {
        res.redirect('/manager/');
    } else if (userType === "employee") {
        res.redirect('/employee/');
    } else {
        res.redirect('/admin/');
    }
});

// Trang hiển thị danh sách người dùng kiểu "employee"
router.get('/dummy', isLoggedIn, async (req, res, next) => {
    try {
        const userChunks = await User.find({ type: 'employee' }).lean();
        res.render('dummy', { title: 'Dummy', users: userChunks });
    } catch (err) {
        console.error('Lỗi khi truy vấn dữ liệu:', err);
        next(err);
    }
});

module.exports = router;
