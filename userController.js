const ErrorHander = require('../utils/errorHandler');
const catchAsyncErrors = require('../middlewares/catchAsyncErrors');
const User = require('../models/userModel');
const sendToken = require('../utils/jwtToken');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');
const nodeMailer = require('nodemailer');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require('dotenv').config();

// Register a User
const registerUser = catchAsyncErrors(async (req, res, next) => {
    const { name, email, password, phone, courseName, university, profession } = req.body;
    const user = await User.create({
        name,
        email,
        password,
        phone,
        courseName,
        university,
        profession,
    });
    sendToken(user, 201, res);
});

// Login User
const loginUser = catchAsyncErrors(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(new ErrorHander('Please Enter Email & Password', 400));
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user) {
        return next(new ErrorHander('Invalid email or password', 401));
    }

    const isPasswordMatched = await user.comparePassword(password);

    if (!isPasswordMatched) {
        return next(new ErrorHander('Invalid email or password', 401));
    }

    sendToken(user, 200, res);
});

// Logout User
const logout = catchAsyncErrors(async (req, res, next) => {
    res.cookie('token', null, {
        expires: new Date(Date.now()),
        httpOnly: true,
    });

    res.status(200).json({
        success: true,
        message: 'Logged Out',
    });
});


const EmailVerification = async (req, res) => {

    const { email } = req.body
    console.log(email)

    const user = await User.findOne({ email })
    if (!user) {
        res.status(422).json({ message: "Email does not exist" })
    } else {

        const randomNumber = crypto.randomInt(0, 10000)
        const OTP = String(randomNumber).padStart(4, '5');

        const resetToken = jwt.sign({ email, OTP }, process.env.JWT_SECRET);
        console.log(resetToken)


        const emailProvider = nodeMailer.createTransport({
            service: "gmail",
            secure: true,
            port: 465, // gmail by default port is 465
            auth: {
                user: "khyatigrover24@gmail.com",
                pass: "password", // fir apko gmail ka password dena hai kuch aisa agr aapke gmail pe 2 step authentication on h to
            },
            tls: { rejectUnauthorized: false },
        });

        const receiver = {
            from: "khyatigrover24@gmail.com",
            to: email,
            subject: "OTP Verification",
            text: `Your One Time Password(OTP) is ${OTP}`,
        };

        emailProvider.sendMail(receiver, (error, emailResponse) => {
            if (error) {
                res.status(422).json({ message: error });
                console.log(error)
            } else {
                const options = {
                    expire: new Date(Date.now() + 60 * 1000),
                    httpOnly: true,
                    secure: true,
                };
                res
                    .cookie("resetpassToken", resetToken, options)
                    .status(200)
                    .json({ message: "OTP send on your Email Address" })
            }
        });

    }
}

// otp verification

const otpverification = async (req, res) => {
    const { otp } = req.body
    const userOtp = req.cookies.resetpassToken
    if (!userOtp) {
        res.status(422).json({ message: "token expired" })
    } else {
        const user = jwt.verify(userOtp, process.env.JWT_SECRET)
        const checkOtp = user.OTP
        if (checkOtp === otp) {
            res.status(200).json({ message: "Otp verified" })
        } else {
            res.status(422).json({ message: "Invalid otp" })
        }
    }

}


//change password
const changepassword = async (req, res) => {
    const { password } = req.body

    const hashPassowrd = await bcrypt.hash(password, 10);

    const resetToken = req.cookies.resetpassToken

    if (!resetToken) {
        res.json({ message: "Token Expired" }).status(422)
    } else {
        const checkToken = jwt.verify(resetToken, process.env.JWT_SECRET);

        const email = checkToken.email
        if (!email) {
            res.json(422).json({ message: "Email is not verified" })
        } else {

            const user = await userModel.findOne({ email })
            user.password = hashPassowrd
            await user.save()
            res
                .clearCookie("resetpassToken")
                .status(200)
                .json({ message: "Password has been changed" })
        }
    }
}





// Get User Details
const getUserDetails = catchAsyncErrors(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found',
        });
    }

    res.status(200).json({
        success: true,
        user,
    });
});

// Update User Details
const updateUserDetails = catchAsyncErrors(async (req, res, next) => {
    const userDetails = req.user;

    const { name, phone, courseName, university, profession } = req.body;

    const obj = {
        name,
        phone,
        courseName,
        university,
        profession,
    };

    const user = await User.findByIdAndUpdate(userDetails.id, obj, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success: true,
        user,
    });
});

// Get User Bookmarked PDFs
const getUserBookmarkedPDFs = catchAsyncErrors(async (req, res, next) => {
    const user = await User.findById(req.user.id).populate('bookmarkedPDFs');

    if (!user) {
        return next(new ErrorHander('User not found', 404));
    }

    res.status(200).json({
        success: true,
        bookmarkedPDFs: user.bookmarkedPDFs,
    });
});

// Add Bookmark
const addBookmark = catchAsyncErrors(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    if (!user) {
        return next(new ErrorHander('User not found', 404));
    }

    const { pdfId } = req.body;

    if (!pdfId) {
        return next(new ErrorHander('PDF ID is required', 400));
    }

    if (!user.bookmarkedPDFs.includes(pdfId)) {
        user.bookmarkedPDFs.push(pdfId);
        await user.save();
    }

    res.status(200).json({
        success: true,
        message: 'PDF bookmarked successfully',
        bookmarkedPDFs: user.bookmarkedPDFs,
    });
});

// Remove Bookmark
const removeBookmark = catchAsyncErrors(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    if (!user) {
        return next(new ErrorHander('User not found', 404));
    }

    const { pdfId } = req.body;

    if (!pdfId) {
        return next(new ErrorHander('PDF ID is required', 400));
    }

    user.bookmarkedPDFs = user.bookmarkedPDFs.filter(
        (bookmark) => bookmark.toString() !== pdfId
    );
    await user.save();

    res.status(200).json({
        success: true,
        message: 'PDF removed from bookmarks successfully',
        bookmarkedPDFs: user.bookmarkedPDFs,
    });
});

const googleAuthCallback = catchAsyncErrors(async (req, res, next) => {
    try {
        if (!req.user) {
            return next(new ErrorHander('User not found after Google authentication', 401));
        }

        const user = await User.findById(req.user.id);

        if (!user) {
            return next(new ErrorHander('User not found', 404));
        }

        res.status(200).json({
            success: true,
            user,
        });
    } catch (error) {
        return next(new ErrorHander(error.message, 500));
    }
});


module.exports = {
    registerUser,
    loginUser,
    logout,

    EmailVerification,
    otpverification,

    changepassword,
    getUserDetails,
    updateUserDetails,
    getUserBookmarkedPDFs,
    addBookmark,
    removeBookmark,
    googleAuthCallback,
};
