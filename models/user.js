const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs'); // Sử dụng đúng phiên bản bcrypt
require('mongoose-type-email');

const Schema = mongoose.Schema;

const UserSchema = new Schema({
    type: { type: String },
    email: { type: mongoose.SchemaTypes.Email, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    contactNumber: { type: String, required: true },
    department: { type: String },
    skills: [{ type: String }], // camelCase
    designation: { type: String },
    dateAdded: { type: Date, default: Date.now }
});

// Mã hóa mật khẩu trước khi lưu
UserSchema.pre('save', function (next) {
    if (!this.isModified('password')) return next();

    bcrypt.genSalt(3, (err, salt) => {
        if (err) return next(err);
        bcrypt.hash(this.password, salt, null, (err, hash) => {
            if (err) return next(err);
            this.password = hash;
            next();
        });
    });
});

// Kiểm tra mật khẩu hợp lệ
UserSchema.methods.validPassword = function (password) {
    return bcrypt.compareSync(password, this.password);
};

// Export model User
module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
