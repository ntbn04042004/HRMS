// Import các thư viện cần thiết
const express = require('express');
const session = require('express-session');
const csrf = require('csurf');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const MongoStore = require('connect-mongo');
const path = require('path');

// Import các route
const index = require('./routes/index');
const users = require('./routes/users');
const admin = require('./routes/admin');
const employee = require('./routes/employee');
const manager = require('./routes/manager');

const app = express();

// Kết nối MongoDB
const mongoDB = 'mongodb://localhost:27017/HRMS';
mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connection successful...'))
    .catch((err) => console.error('MongoDB connection failed...', err));

// Import passport cấu hình
require('./config/passport.js');

// Middleware
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Cấu hình view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


// Cấu hình session với MongoDB
app.use(session({
    secret: 'mysupersecret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoDB,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60, // 14 ngày
        autoRemove: 'native' // Tự động xóa session hết hạn
    }),
    cookie: { maxAge: 180 * 60 * 1000 } // 3 giờ
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));

// Khởi tạo CSRF protection
const csrfProtection = csrf({ cookie: true });

// Cung cấp biến toàn cục cho view
app.use((req, res, next) => {
    res.locals.login = req.isAuthenticated() ? true : false;      res.locals.session = req.session;
    res.locals.messages = req.flash();
    next();
});

// Route GET /login để hiển thị form login
app.get('/login', (req, res) => {
    res.render('login', { csrfToken: req.csrfToken() });
});

// Route POST /login để xử lý đăng nhập
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    // Xử lý đăng nhập ở đây
    res.send('Login successful!');
});

// Khởi động server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});

app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken ? req.csrfToken() : null;
    next();
});

// Các route
app.use('/', csrfProtection, index);
app.use('/users',csrfProtection, users);
app.use('/admin',csrfProtection, admin);
app.use('/manager',csrfProtection, manager);
app.use('/employee',csrfProtection, employee);

// Xử lý lỗi 404
app.use((req, res, next) => {
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// Xử lý lỗi chung
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403).send('Invalid CSRF Token');
        return;
    }
app.use((err, req, res, next) => {
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(err.status || 500);
    res.render('error');
});
});
module.exports = app;