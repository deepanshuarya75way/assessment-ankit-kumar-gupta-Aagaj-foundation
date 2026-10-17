const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const Razorpay = require('razorpay');
const HealthCard = require('../models/HealthCardSchema');
const HealthCardOtp = require('../models/HealthCardOtp');
const PendingPayment = require('../models/PendingPayment');
const PaymentLog = require('../models/PaymentLog');
const crypto = require('crypto');
const { sendSMS, sendWhatsApp } = require('../services/twilioService');
const { sendOtpSMS, sendMsg91WidgetOtp, verifyMsg91WidgetOtp, maskMobileNumber } = require('../services/smsService');
const { sendHealthCardConfirmation, sendHealthCardOtpEmail, maskEmail } = require('../services/emailService');
const { validateRequest } = require('../middleware/requestValidation');
const {
    healthCardCheckExistsSchema,
    healthCardCreateOrderSchema,
    healthCardVerifyPaymentSchema
} = require('../utils/routeSchemas');

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'rzp_test_placeholder'
});

// ✅ FILE FILTER - Only Images
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
        return cb(null, true);
    } else {
        cb(new Error('Only image files (JPEG, JPG, PNG, GIF) are allowed!'));
    }
};

const upload = require('../middleware/upload');

const { verifyAdmin, verifyAdminOrEmployee } = require('../middleware/auth');

// ✅ API to Check if User Already Exists
router.post('/check-exists', validateRequest({ body: healthCardCheckExistsSchema }), async (req, res) => {
    try {
        const { mobile, aadhar } = req.body;
        
        let queryArr = [];
        if (mobile) queryArr.push({ mobile });
        if (aadhar) queryArr.push({ aadhar });

        if (queryArr.length === 0) return res.json({ exists: false });

        const existingUser = await HealthCard.findOne({ $or: queryArr });

        if (existingUser) {
            return res.json({ 
                exists: true, 
                message: "This contact number or aadhar number is already exist" 
            });
        }

        res.json({ exists: false });
    } catch (error) {
        console.error("Check Exists Error:", error);
        res.status(500).json({ exists: false, message: "Server Error" });
    }
});

// ✅ API to Create Payment Order (RAZORPAY)
router.post('/create-order', upload.single('photo'), validateRequest({ body: healthCardCreateOrderSchema }), async (req, res) => {
    try {
        if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
            return res.status(500).json({ success: false, message: 'Payment gateway not configured. Please contact administrator.' });
        }

        const {
            fullName, mobile, aadhar, age, gender, bloodGroup,
            village, panchayat, block, district, state, pincode,
            registeredBy, cardType, familyMembers
        } = req.body;

        // 1. Validation
        if (!fullName || !mobile || !aadhar || !age) {
            return res.json({ success: false, message: "Missing required fields" });
        }

        // 2. Check for duplicates
        const existingUser = await HealthCard.findOne({ $or: [{ mobile }, { aadhar }] });
        if (existingUser) {
            return res.json({ success: false, message: "Data already exists for this Mobile or Aadhar." });
        }

        // 3. Generate Order ID
        const orderId = `HLTHCRD${Date.now()}`;

        const resolvedCardType = cardType || 'Single';
        const finalAmount = resolvedCardType === 'Family' ? 499 : 201;

        let familyMembersParsed = [];
        if (resolvedCardType === 'Family' && familyMembers) {
            try {
                familyMembersParsed = typeof familyMembers === 'string' ? JSON.parse(familyMembers) : familyMembers;
            } catch (e) {
                console.error("Family members parsing failed:", e.message);
            }
        }

        // 4. Store pending data in MongoDB (TTL 60 minutes)
        await PendingPayment.create({
            orderId: orderId,
            paymentType: 'healthcard',
            data: {
                fullName, mobile, aadhar, age, gender, bloodGroup,
                village, panchayat, block, district, state, pincode,
                photoPath: req.file ? req.file.path : '',
                registeredBy: registeredBy || 'Self',
                cardType: resolvedCardType,
                familyMembers: familyMembersParsed,
                amount: finalAmount
            }
        });

        // 5. Create Razorpay order
        const order = await razorpay.orders.create({
            amount: finalAmount * 100,
            currency: 'INR',
            receipt: orderId,
            notes: {
                paymentType: 'healthcard',
                pendingOrderId: orderId,
                fullName: fullName || 'Health Card User',
                mobile: mobile || '',
                cardType: resolvedCardType
            }
        });

        return res.json({
            success: true,
            orderId: order.id,
            pendingOrderId: orderId,
            amount: order.amount,
            currency: order.currency,
            key: process.env.RAZORPAY_KEY_ID
        });

    } catch (error) {
        console.error("Create Order Error:", error);
        res.status(500).json({ success: false, message: "Server Error: " + error.message });
    }
});

// ✅ API to Verify Payment Callback (RAZORPAY)
router.post('/verify-payment', validateRequest({ body: healthCardVerifyPaymentSchema }), async (req, res) => {
    try {
        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature,
            pendingOrderId
        } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !pendingOrderId) {
            return res.status(400).json({ success: false, message: 'Missing payment verification fields' });
        }

        const generatedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(`${razorpay_order_id}|${razorpay_payment_id}`)
            .digest('hex');

        if (generatedSignature !== razorpay_signature) {
            return res.status(400).json({ success: false, message: 'Payment signature verification failed' });
        }

        // 3. Retrieve pending card data from MongoDB
        const pendingRecord = await PendingPayment.findOne({ 
            orderId: pendingOrderId,
            paymentType: 'healthcard'
        });

        if (!pendingRecord) {
            console.error('No pending health card found for order:', pendingOrderId);
            return res.status(404).json({ success: false, message: 'Pending order not found' });
        }

        const pendingCardData = pendingRecord.data;

        // 4. Generate Health ID
        const randomNum = Math.floor(100000 + Math.random() * 900000);
        const healthId = `MC-${randomNum}`;

        // 5. Calculate Expiry Date (6 months)
        const expiryDate = new Date();
        expiryDate.setMonth(expiryDate.getMonth() + 6);

        // 6. Save to Database
        const newCard = new HealthCard({
            healthId,
            fullName: pendingCardData.fullName,
            mobile: pendingCardData.mobile,
            email: pendingCardData.email,
            aadhar: pendingCardData.aadhar,
            age: pendingCardData.age,
            gender: pendingCardData.gender,
            bloodGroup: pendingCardData.bloodGroup,
            address: {
                village: pendingCardData.village,
                panchayat: pendingCardData.panchayat,
                block: pendingCardData.block,
                district: pendingCardData.district,
                state: pendingCardData.state,
                pincode: pendingCardData.pincode
            },
            photoPath: pendingCardData.photoPath,
            cardType: pendingCardData.cardType || 'Single',
            familyMembers: pendingCardData.familyMembers || [],
            paymentId: razorpay_payment_id,
            orderId: pendingOrderId,
            amount: pendingCardData.amount || 201,
            paymentStatus: 'Paid',
            expiryDate,
            registeredBy: pendingCardData.registeredBy || 'Self'
        });

        await newCard.save();

        // 7. Clean up pending record from MongoDB immediately
        await PendingPayment.deleteOne({ orderId: pendingOrderId });

        const frontendUrl = process.env.FRONTEND_URL || 'https://aagajfoundation.com';
        const responsePayload = {
            success: true,
            orderId: pendingOrderId,
            paymentId: razorpay_payment_id,
            card: newCard,
            redirectUrl: `${frontendUrl}/medical/healthcard?status=success&orderId=${encodeURIComponent(pendingOrderId)}&paymentId=${encodeURIComponent(razorpay_payment_id)}`
        };

        // 🟢 Execute Email, SMS, WhatsApp, and PaymentLog asynchronously in background (Non-blocking)
        setImmediate(async () => {
            try {
                if (newCard.email) {
                    await sendHealthCardConfirmation(newCard);
                }
            } catch (mailError) {
                console.warn('Health card confirmation email background failed:', mailError.message);
            }

            if (pendingCardData.mobile) {
                try {
                    const cardTypeTitle = (pendingCardData.cardType || 'Single') === 'Family' ? 'Family Health Card' : 'Health Card';
                    const healthCardMsg = `Dear ${pendingCardData.fullName}, your payment was successful! Your ${cardTypeTitle} ID is ${healthId}. It is valid until ${expiryDate.toLocaleDateString('en-IN')}. Thank you!`;
                    await Promise.all([
                        sendSMS(pendingCardData.mobile, healthCardMsg),
                        sendWhatsApp(pendingCardData.mobile, healthCardMsg)
                    ]);
                } catch (notifyErr) {
                    console.warn('Health card SMS/WA notification background error:', notifyErr.message);
                }
            }

            try {
                await PaymentLog.create({
                    orderId: pendingOrderId,
                    amount: pendingCardData.amount || 201,
                    status: 'success',
                    paymentId: razorpay_payment_id,
                    transactionId: razorpay_order_id,
                    schemeType: 'healthcard',
                    ipAddress: req.ip || req.connection?.remoteAddress,
                    userAgent: req.get('User-Agent'),
                    rawResponse: req.body,
                    verificationStatus: 'verified',
                    amountVerified: true,
                    signatureVerified: true
                });
            } catch (logError) {
                console.warn('PaymentLog write failed (healthcard):', logError.message);
            }
        });

        return res.json(responsePayload);

    } catch (error) {
        console.error("Verify Payment Error:", error);
        return res.status(500).json({ success: false, message: 'Payment verification failed' });
    }
});

// ✅ API to Fetch Card Data by Order ID (for print restoration)
router.get('/get-by-order/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { paymentId, healthId } = req.query;

        const cleanOrderId = String(orderId || '').trim();
        const cleanPaymentId = String(paymentId || '').trim();
        const cleanHealthId = String(healthId || '').trim();

        // Build flexible query to find card by any available identifier
        const queries = [];
        if (cleanOrderId && cleanOrderId !== 'undefined' && cleanOrderId !== 'null') {
            queries.push({ orderId: cleanOrderId });
            queries.push({ healthId: cleanOrderId });
            if (!cleanOrderId.startsWith('MC-') && /^\d{6}$/.test(cleanOrderId)) {
                queries.push({ healthId: `MC-${cleanOrderId}` });
            }
        }
        if (cleanPaymentId && cleanPaymentId !== 'undefined' && cleanPaymentId !== 'null') {
            queries.push({ paymentId: cleanPaymentId });
        }
        if (cleanHealthId && cleanHealthId !== 'undefined' && cleanHealthId !== 'null') {
            queries.push({ healthId: cleanHealthId });
            if (!cleanHealthId.startsWith('MC-') && /^\d{6}$/.test(cleanHealthId)) {
                queries.push({ healthId: `MC-${cleanHealthId}` });
            }
        }

        if (queries.length === 0) {
            return res.status(400).json({ success: false, message: "No search identifier provided" });
        }

        const card = await HealthCard.findOne({ $or: queries });

        if (!card) {
            return res.json({ success: false, message: "Card not found in database" });
        }

        res.json({ success: true, data: card });
    } catch (error) {
        console.error("Get Card Error:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// Helper function to hash OTP securely
const hashOtp = (otp) => {
    const { getJwtSecret } = require('../middleware/auth');
    const secret = getJwtSecret();
    return crypto.createHmac('sha256', secret).update(String(otp).trim()).digest('hex');
};

// Middleware to verify Health Card Access Token (issued only after successful OTP verification)
const verifyCardAccessToken = (req, res, next) => {
    const authHeader = req.header('Authorization') || req.header('x-card-token');
    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: "Access Denied. OTP verification required to view or download Health Card."
        });
    }

    const tokenVal = authHeader.replace("Bearer ", "").trim();

    try {
        const { getJwtSecret } = require('../middleware/auth');
        const decoded = jwt.verify(tokenVal, getJwtSecret());
        if (decoded.role === 'admin' || decoded.role === 'employee') {
            return next();
        }
        if (decoded.scope !== 'healthcard_access') {
            return res.status(403).json({
                success: false,
                message: "Access Denied. Invalid token scope."
            });
        }

        const reqHealthId = String(req.params.healthId || '').toUpperCase().trim().replace(/^MC-/, '');
        const tokenHealthId = String(decoded.healthId || '').toUpperCase().trim().replace(/^MC-/, '');

        if (reqHealthId !== tokenHealthId) {
            return res.status(403).json({
                success: false,
                message: "Access Denied. Token does not match requested Health ID."
            });
        }

        req.cardAccess = decoded;
        next();
    } catch (err) {
        return res.status(401).json({
            success: false,
            message: "Session expired or invalid token. Please complete OTP verification again."
        });
    }
};

// ✅ STEP 1 API: Request OTP for Health Card Access (Sent to Registered Mobile via MSG91 Widget)
router.post('/request-otp', async (req, res) => {
    try {
        const inputId = String(req.body.healthId || '').trim();
        if (!inputId) {
            return res.status(400).json({ success: false, message: 'Please enter a valid Health Card ID.' });
        }

        const upper = inputId.toUpperCase();
        const candidates = new Set([inputId, upper]);
        if (/^\d{6}$/.test(inputId)) candidates.add(`MC-${inputId}`);
        const match = upper.match(/^MC-(\d{6})$/);
        if (match) candidates.add(match[1]);

        const candidateArray = Array.from(candidates).filter(Boolean);
        const card = await HealthCard.findOne({ healthId: { $in: candidateArray } });

        if (!card) {
            return res.status(404).json({
                success: false,
                message: 'Health ID card not found. Please check your card number.'
            });
        }

        if (!card.mobile) {
            return res.status(400).json({
                success: false,
                message: 'No registered mobile number found for this Health ID. Please contact support.'
            });
        }

        const maskedMobile = maskMobileNumber(card.mobile);

        // Rate Limit & Cooldown Check (60 seconds resend timer)
        const existingSession = await HealthCardOtp.findOne({ healthId: card.healthId });
        if (existingSession && Date.now() < existingSession.resendAvailableAt.getTime()) {
            const waitSeconds = Math.ceil((existingSession.resendAvailableAt.getTime() - Date.now()) / 1000);
            return res.status(429).json({
                success: false,
                message: `Please wait ${waitSeconds} seconds before requesting a new OTP.`,
                resendTimer: waitSeconds,
                sessionId: existingSession.sessionId,
                maskedMobile
            });
        }

        // Dispatch OTP via MSG91 Widget API
        let reqId = '';
        try {
            const result = await sendMsg91WidgetOtp(card.mobile);
            reqId = result.reqId;
        } catch (err) {
            console.error("MSG91 Widget Send OTP Error:", err.message);
            return res.status(500).json({
                success: false,
                message: 'Failed to send OTP to mobile: ' + (err.message || 'SMS Gateway Error')
            });
        }

        const sessionId = crypto.randomBytes(16).toString('hex');
        const now = Date.now();
        const expiresAt = new Date(now + 5 * 60 * 1000); // 5 mins validity
        const resendAvailableAt = new Date(now + 60 * 1000); // 60s cooldown

        await HealthCardOtp.findOneAndUpdate(
            { healthId: card.healthId },
            {
                healthId: card.healthId,
                sessionId,
                mobile: card.mobile,
                email: card.email || '',
                reqId,
                attempts: 0,
                maxAttempts: 5,
                resendAvailableAt,
                expiresAt
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: `OTP sent to registered mobile number (${maskedMobile})`,
            sessionId,
            healthId: card.healthId,
            maskedMobile,
            resendTimer: 60,
            expiresMinutes: 5
        });

    } catch (error) {
        console.error("Request OTP Error:", error);
        res.status(500).json({ success: false, message: "Server Error: " + error.message });
    }
});

// ✅ STEP 2 API: Verify OTP & Issue Token
router.post('/verify-otp', async (req, res) => {
    try {
        const { healthId, sessionId, otp } = req.body;
        if (!healthId || !sessionId || !otp) {
            return res.status(400).json({ success: false, message: 'Missing required parameters (healthId, sessionId, otp).' });
        }

        const otpSession = await HealthCardOtp.findOne({ sessionId, healthId });
        if (!otpSession) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP session. Please request a new OTP.'
            });
        }

        if (Date.now() > new Date(otpSession.expiresAt).getTime()) {
            await HealthCardOtp.deleteOne({ _id: otpSession._id });
            return res.status(400).json({
                success: false,
                message: 'OTP has expired (validity 5 minutes). Please request a new OTP.'
            });
        }

        if (otpSession.attempts >= otpSession.maxAttempts) {
            return res.status(429).json({
                success: false,
                message: 'Maximum verification attempts (5) exceeded. Please request a new OTP.'
            });
        }

        // Increment attempt count
        otpSession.attempts += 1;
        await otpSession.save();

        // Verify OTP with MSG91 Widget API
        let isVerified = false;
        let verifyMessage = 'Invalid OTP.';

        if (otpSession.reqId) {
            const verifyRes = await verifyMsg91WidgetOtp(otpSession.reqId, otp);
            isVerified = verifyRes.success;
            verifyMessage = verifyRes.message || 'Invalid OTP.';
        } else if (otpSession.otpHash) {
            const inputHash = hashOtp(otp);
            isVerified = (inputHash === otpSession.otpHash);
        }

        if (!isVerified) {
            const remaining = otpSession.maxAttempts - otpSession.attempts;
            if (remaining <= 0) {
                return res.status(429).json({
                    success: false,
                    message: 'Maximum verification attempts (5) exceeded. Please request a new OTP.'
                });
            }
            return res.status(400).json({
                success: false,
                message: `${verifyMessage} You have ${remaining} attempt(s) remaining.`
            });
        }

        // Success: Delete OTP session & issue 15-minute Card Access Token
        await HealthCardOtp.deleteOne({ _id: otpSession._id });

        const cardToken = jwt.sign(
            { healthId: otpSession.healthId, scope: 'healthcard_access' },
            require('../middleware/auth').getJwtSecret(),
            { expiresIn: '15m' }
        );

        res.json({
            success: true,
            message: 'OTP verified successfully!',
            cardToken,
            healthId: otpSession.healthId
        });

    } catch (error) {
        console.error("Verify OTP Error:", error);
        res.status(500).json({ success: false, message: "Server Error: " + error.message });
    }
});

// ✅ STEP 3 API: Fetch Health Card Details (Protected by OTP Access Token)
router.get('/verify/:healthId', verifyCardAccessToken, async (req, res) => {
    try {
        const input = String(req.params.healthId || '').trim();
        const upper = input.toUpperCase();
        const candidates = new Set([input, upper]);

        if (/^\d{6}$/.test(input)) {
            candidates.add(`MC-${input}`);
        }

        const match = upper.match(/^MC-(\d{6})$/);
        if (match) {
            candidates.add(match[1]);
        }

        const candidateArray = Array.from(candidates).filter(Boolean);

        const card = await HealthCard.findOne({ healthId: { $in: candidateArray } }).lean();

        if (!card) {
            return res.status(404).json({ success: false, message: 'Health ID not found. Please check your card number.' });
        }

        // Mask sensitive fields
        if (card.aadhar) {
            card.aadhar = card.aadhar.replace(/.(?=.{4})/g, 'X');
        }
        if (card.mobile) {
            card.mobile = card.mobile.replace(/.(?=.{4})/g, 'X');
        }
        if (card.email) {
            const parts = card.email.split('@');
            if (parts.length === 2) {
                const local = parts[0];
                const domain = parts[1];
                const maskedLocal = local.length > 2 
                    ? local[0] + '*'.repeat(local.length - 2) + local[local.length - 1]
                    : '*'.repeat(local.length);
                card.email = maskedLocal + '@' + domain;
            }
        }
        if (card.familyMembers && Array.isArray(card.familyMembers)) {
            card.familyMembers = card.familyMembers.map(member => {
                if (member.aadhar) {
                    member.aadhar = member.aadhar.replace(/.(?=.{4})/g, 'X');
                }
                return member;
            });
        }

        res.json({ success: true, data: card });
    } catch (error) {
        console.error("Verify Health Card ID Error:", error);
        res.status(500).json({ success: false, message: "Server Error: " + error.message });
    }
});

// ✅ API to get all health cards for Admin Dashboard
router.get('/all', verifyAdminOrEmployee, async (req, res) => {
    try {
        const allCards = await HealthCard.find().sort({ createdAt: -1 }); // Sort by newest
        res.json({ success: true, data: allCards });
    } catch (error) {
        console.error("Get All Health Cards Error:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ✅ API for Admin to directly generate Health Card (Custom Price & Photo)
router.post('/admin/create', verifyAdmin, upload.single('photo'), async (req, res) => {
    try {
        const {
            fullName, mobile, email, aadhar, age, gender, bloodGroup,
            village, panchayat, block, district, state, pincode,
            registeredBy, cardType, familyMembers, amount
        } = req.body;

        // 1. Validation
        if (!fullName || !mobile || !aadhar || !age) {
            return res.status(400).json({ success: false, message: "Missing required fields (Name, Mobile, Aadhar, Age)" });
        }

        if (amount !== undefined && parseInt(amount, 10) < 0) {
            return res.status(400).json({ success: false, message: "Custom fee cannot be negative." });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: "Candidate photo is required to generate health card." });
        }

        // 2. Check for duplicates
        const existingUser = await HealthCard.findOne({ $or: [{ mobile }, { aadhar }] });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Data already exists for this Mobile or Aadhar." });
        }

        const resolvedCardType = cardType || 'Single';
        const finalAmount = amount ? parseInt(amount, 10) : (resolvedCardType === 'Family' ? 499 : 201);

        let familyMembersParsed = [];
        if (resolvedCardType === 'Family' && familyMembers) {
            try {
                familyMembersParsed = typeof familyMembers === 'string' ? JSON.parse(familyMembers) : familyMembers;
            } catch (e) {
                console.error("Family members parsing failed:", e.message);
            }
        }

        // 3. Generate Health ID
        const randomNum = Math.floor(100000 + Math.random() * 900000);
        const healthId = `MC-${randomNum}`;

        // 4. Calculate Expiry Date (6 months)
        const expiryDate = new Date();
        expiryDate.setMonth(expiryDate.getMonth() + 6);

        const mockPaymentId = "OFFLINE_AD_" + Date.now();
        const mockOrderId = "ADMIN_" + Date.now();

        // 5. Save to Database
        const newCard = new HealthCard({
            healthId,
            fullName,
            mobile,
            email,
            aadhar,
            age: parseInt(age, 10),
            gender,
            bloodGroup,
            address: {
                village,
                panchayat,
                block,
                district,
                state,
                pincode
            },
            photoPath: req.file ? req.file.path : '',
            cardType: resolvedCardType,
            familyMembers: familyMembersParsed,
            paymentId: mockPaymentId,
            orderId: mockOrderId,
            amount: finalAmount,
            paymentStatus: 'Paid',
            expiryDate,
            registeredBy: registeredBy || req.user?.email || 'Admin'
        });

        await newCard.save();

        try {
            if (newCard.email) {
                await sendHealthCardConfirmation(newCard);
            }
        } catch (mailError) {
            console.warn('Health card confirmation email failed:', mailError.message);
        }

        // 6. Log Transaction
        try {
            await PaymentLog.create({
                orderId: mockOrderId,
                amount: finalAmount,
                status: 'success',
                paymentId: mockPaymentId,
                transactionId: mockOrderId,
                schemeType: 'healthcard',
                ipAddress: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent'),
                rawResponse: { type: 'admin_direct_creation', admin: req.user?.email },
                verificationStatus: 'verified',
                amountVerified: true,
                signatureVerified: true
            });
        } catch (logError) {
            console.warn('PaymentLog write failed (healthcard admin):', logError.message);
        }

        return res.status(200).json({
            success: true,
            message: "Custom health card generated successfully!",
            data: newCard
        });

    } catch (error) {
        console.error("Admin Direct Health Card Register Error:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Admin & Authorized Staff: Edit Health Card Details
router.put('/admin/edit/:id', verifyAdminOrEmployee, upload.single('photo'), async (req, res) => {
    try {
        const cardId = req.params.id;
        const {
            fullName,
            mobile,
            email,
            aadhar,
            age,
            gender,
            bloodGroup,
            address,
            village,
            panchayat,
            block,
            district,
            state,
            pincode,
            cardType,
            familyMembers,
            expiryDate,
            registeredBy
        } = req.body;

        // Validation
        if (!fullName || !mobile || !aadhar || !age || !gender || !bloodGroup) {
            return res.status(400).json({ success: false, message: "Required fields (Name, Mobile, Aadhar, Age, Gender, Blood Group) cannot be empty" });
        }

        // Check if card exists
        const existingCard = await HealthCard.findById(cardId);
        if (!existingCard) {
            return res.status(404).json({ success: false, message: "Health card not found" });
        }

        // Check unique fields duplicate except this card
        const duplicateCheck = await HealthCard.findOne({
            _id: { $ne: cardId },
            $or: [
                { mobile },
                { aadhar }
            ]
        });

        if (duplicateCheck) {
            if (duplicateCheck.mobile === mobile) {
                return res.status(400).json({ success: false, message: "Mobile number is already registered on another health card!" });
            }
            if (duplicateCheck.aadhar === aadhar) {
                return res.status(400).json({ success: false, message: "Aadhar card number is already registered on another health card!" });
            }
        }

        // Update fields
        existingCard.fullName = fullName;
        existingCard.mobile = mobile;
        existingCard.email = email || '';
        existingCard.aadhar = aadhar;
        existingCard.age = parseInt(age, 10) || existingCard.age;
        existingCard.gender = gender;
        existingCard.bloodGroup = bloodGroup;

        // Parse Address
        let parsedAddress = existingCard.address || {};
        if (address) {
            try {
                parsedAddress = typeof address === 'string' ? JSON.parse(address) : address;
            } catch (e) {
                parsedAddress = { village, panchayat, block, district, state, pincode };
            }
        } else {
            parsedAddress = {
                village: village !== undefined ? village : parsedAddress.village,
                panchayat: panchayat !== undefined ? panchayat : parsedAddress.panchayat,
                block: block !== undefined ? block : parsedAddress.block,
                district: district !== undefined ? district : parsedAddress.district,
                state: state !== undefined ? state : parsedAddress.state,
                pincode: pincode !== undefined ? pincode : parsedAddress.pincode
            };
        }
        existingCard.address = parsedAddress;

        existingCard.cardType = cardType || existingCard.cardType;
        if (registeredBy) {
            existingCard.registeredBy = registeredBy;
        }

        if (familyMembers) {
            try {
                existingCard.familyMembers = Array.isArray(familyMembers) ? familyMembers : JSON.parse(familyMembers);
            } catch (e) {
                console.error("Family members parse error on edit:", e.message);
            }
        }
        if (expiryDate) {
            existingCard.expiryDate = new Date(expiryDate);
        }
        if (req.file) {
            existingCard.photoPath = req.file.path;
        }

        await existingCard.save();

        res.json({
            success: true,
            message: "Health card details updated successfully!",
            data: existingCard
        });
    } catch (error) {
        console.error("Edit Health Card Error:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

module.exports = router;
