const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const GenericOtp = require('../models/GenericOtpSchema');
const { sendMsg91WidgetOtp, verifyMsg91WidgetOtp, maskMobileNumber, formatIndianMobile } = require('./smsService');

/**
 * Initiate an OTP request for any scope using MSG91 Widget API
 */
const requestOtpSession = async ({ identifier, scope, mobile, metadata = {} }) => {
    if (!identifier || !scope || !mobile) {
        throw new Error('Missing required OTP initiation parameters (identifier, scope, mobile).');
    }

    const cleanMobile = formatIndianMobile(mobile);
    if (!cleanMobile || cleanMobile.length < 10) {
        throw new Error('Invalid mobile number provided for OTP dispatch.');
    }

    const maskedMobile = maskMobileNumber(cleanMobile);
    const sessionKey = `${scope}_${identifier}`.toLowerCase();

    // Rate limit check (60 seconds cooldown)
    const existingSession = await GenericOtp.findOne({ identifier: sessionKey, scope });
    if (existingSession && Date.now() < existingSession.resendAvailableAt.getTime()) {
        const waitSeconds = Math.ceil((existingSession.resendAvailableAt.getTime() - Date.now()) / 1000);
        return {
            rateLimited: true,
            message: `Please wait ${waitSeconds} seconds before requesting a new OTP.`,
            resendTimer: waitSeconds,
            sessionId: existingSession.sessionId,
            maskedMobile
        };
    }

    // Trigger SMS via MSG91 Widget API
    const result = await sendMsg91WidgetOtp(cleanMobile);
    const reqId = result.reqId;

    const sessionId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const expiresAt = new Date(now + 5 * 60 * 1000); // 5 mins validity
    const resendAvailableAt = new Date(now + 60 * 1000); // 60s cooldown

    await GenericOtp.findOneAndUpdate(
        { identifier: sessionKey, scope },
        {
            identifier: sessionKey,
            scope,
            sessionId,
            reqId,
            attempts: 0,
            maxAttempts: 5,
            resendAvailableAt,
            expiresAt,
            metadata: {
                ...metadata,
                mobile: cleanMobile,
                maskedMobile
            }
        },
        { upsert: true, new: true }
    );

    return {
        success: true,
        message: `OTP sent to registered mobile number (${maskedMobile})`,
        sessionId,
        maskedMobile,
        resendTimer: 60,
        expiresMinutes: 5
    };
};

/**
 * Verify an OTP session for any scope using MSG91 Widget API
 */
const verifyOtpSession = async ({ sessionId, scope, otp }) => {
    if (!sessionId || !scope || !otp) {
        return { success: false, message: 'Missing required verification parameters (sessionId, scope, otp).' };
    }

    const otpSession = await GenericOtp.findOne({ sessionId, scope });
    if (!otpSession) {
        return { success: false, message: 'Invalid or expired OTP session. Please request a new OTP.' };
    }

    if (Date.now() > new Date(otpSession.expiresAt).getTime()) {
        await GenericOtp.deleteOne({ _id: otpSession._id });
        return { success: false, message: 'OTP has expired (validity 5 minutes). Please request a new OTP.' };
    }

    if (otpSession.attempts >= otpSession.maxAttempts) {
        return { success: false, message: 'Maximum verification attempts (5) exceeded. Please request a new OTP.' };
    }

    // Increment attempt count
    otpSession.attempts += 1;
    await otpSession.save();

    // Verify OTP via MSG91 Widget API
    const verifyRes = await verifyMsg91WidgetOtp(otpSession.reqId, otp);
    if (!verifyRes.success) {
        const remaining = otpSession.maxAttempts - otpSession.attempts;
        if (remaining <= 0) {
            return {
                success: false,
                message: 'Maximum verification attempts (5) exceeded. Please request a new OTP.'
            };
        }
        return {
            success: false,
            message: `${verifyRes.message || 'Incorrect OTP.'} You have ${remaining} attempt(s) remaining.`
        };
    }

    // Success: Generate verification access token
    const tokenPayload = {
        scope,
        identifier: otpSession.identifier,
        metadata: otpSession.metadata || {}
    };

    const accessToken = jwt.sign(
        tokenPayload,
        require('../middleware/auth').getJwtSecret(),
        { expiresIn: '15m' }
    );

    const savedMetadata = otpSession.metadata;

    // Remove OTP session
    await GenericOtp.deleteOne({ _id: otpSession._id });

    return {
        success: true,
        message: 'OTP verified successfully!',
        accessToken,
        metadata: savedMetadata
    };
};

module.exports = {
    requestOtpSession,
    verifyOtpSession
};
