const express = require('express');
const passport = require('passport');
require('../config/passportConfig');
const {
    registerUser,
    loginUser,
    logout,
    // forgotPassword,
    EmailVerification,
    // resetPassword,
    changepassword,
    otpverification,
    getUserDetails,
    updateUserDetails,
    getUserBookmarkedPDFs,
    addBookmark,
    removeBookmark,
    googleAuthCallback,
} = require('../controllers/userController');
const { isAuthenticatedUser } = require('../middlewares/auth');
const router = express.Router();

router.route('/').put(isAuthenticatedUser, updateUserDetails);
router.route('/signin').post(loginUser);
router.route('/signup').post(registerUser);
router.route('/signout').get(logout);
router.route('/EmailVerification').post(EmailVerification);
router.route('/otpverification').post(otpverification);
// router.route('/resetpass').put(resetPassword);
router.route('/changepassword').put(changepassword);
router.route('/me').get(isAuthenticatedUser, getUserDetails);
router.route('/bookmarked-pdfs').get(isAuthenticatedUser, getUserBookmarkedPDFs);
router.route('/bookmark-pdf').post(isAuthenticatedUser, addBookmark);
router.route('/bookmark-pdf').delete(isAuthenticatedUser, removeBookmark);

// router.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
// router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), googleAuthCallback);

module.exports = router;
