// Import các thư viện cần thiết
const express = require('express');
const router = express.Router();
const User = require('../models/user.js');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const csrf = require('csurf');

const csrfProtection = csrf();

// Middleware xác thực quyền admin (ví dụ)
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ message: 'Access denied. Admins only.' });
};


// Lấy danh sách người dùng
router.get('/', async (req, res) => {
    try {
        const users = await User.find().select('-password'); // Không trả về password
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Lấy thông tin người dùng theo ID
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Tạo người dùng mới (Chỉ dành cho admin hoặc qua hệ thống nội bộ)
router.post(
    '/admin',
    csrfProtection,
    isAdmin, // Chỉ cho phép admin truy cập
    [
        body('email').isEmail().withMessage('Invalid email'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
        body('name').notEmpty().withMessage('Name is required'),
        body('type').isIn(['admin', 'user']).withMessage('Invalid user type'),
        body('dateOfBirth').optional().isISO8601().withMessage('Invalid date format'),
        body('contactNumber').optional().isMobilePhone().withMessage('Invalid contact number'),
        body('department').optional().isString().withMessage('Department must be a string'),
        body('skills').optional().isArray().withMessage('Skills must be an array'),
        body('designation').optional().isString().withMessage('Designation must be a string')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { type, email, password, name, dateOfBirth, contactNumber, department, skills, designation } = req.body;

            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ message: 'Email already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = new User({
                type,
                email,
                password: hashedPassword,
                name,
                dateOfBirth,
                contactNumber,
                department,
                skills,
                designation
            });

            const savedUser = await newUser.save();
          
  res.status(201).json({
	...savedUser.toObject(),
	password: undefined

});
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    }
);

// Cập nhật thông tin người dùng
router.put(
    '/:id',
     csrfProtection,
    [
        body('email').optional().isEmail().withMessage('Invalid email'),
        body('name').optional().notEmpty().withMessage('Name is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { name, email } = req.body;

            const updatedUser = await User.findByIdAndUpdate(
                req.params.id,
                { name, email },
                { new: true, runValidators: true }
            ).select('-password');

            if (!updatedUser) return res.status(404).json({ message: 'User not found' });

            res.json(updatedUser);
        } catch (error) {
            res.status(400).json({ message: error.message });
        }
    }
);

// Xóa người dùng
router.delete('/:id',  csrfProtection, async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;
