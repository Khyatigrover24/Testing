const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    googleId: {
        type: String,
        unique: true,
        sparse: true,
    },
    name: {
        type: String,
        required: [true, 'Please Enter Your Name'],
        maxLength: [30, 'Name cannot exceed 30 characters'],
        minLength: [4, 'Name should have more than 4 characters']
    },
    email: {
        type: String,
        required: [true, 'Please Enter Your Email'],
        validate: [validator.isEmail, 'Please Enter a valid Email'],
        unique: [true, 'this email is already registered']
    },
    password: {
        type: String,
        // Only require password for non-Google users
        required: function () { return !this.googleId },
        minLength: [8, 'Password should be greater than 8 characters'],
        select: false
    },
    phone: {
        type: String,
        // Only require phone for non-Google users
        required: function () { return !this.googleId },
        maxLength: [25, 'phone number must be less than 20']
    },
    profession: {
        type: String
    },
    university: {
        type: String
    },
    courseName: {
        type: String
    },
    role: {
        type: String,
        default: 'user'
    },
    otp: {
        type: Number,
        required: false
    },
    otpExpiry: {
        type: Date,
        required: false
    },
    avatar: {
        public_id: {
            type: String
        },
        url: {
            type: String
        }
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    resetPasswordOTP: String,
    resetPasswordOTPExpire: Date,
    bookmarkedPDFs: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'PDF'
        }
    ]
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        next();
    }

    this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.getJWTToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE
    });
};

userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};



userSchema.methods.generateOTP = function () {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    this.resetPasswordOTP = crypto.createHash('sha256').update(otp).digest('hex');
    this.resetPasswordOTPExpire = Date.now() + 15 * 60 * 1000; // OTP valid for 15 minutes

    return otp;
};

module.exports = mongoose.model('User', userSchema);