const express = require('express');
const router = express.Router();
const Appointment = require('../models/AppointmentSchema');
const HealthPartner = require('../models/SwasthyaSurkshaSchema');
const HealthCard = require('../models/HealthCardSchema');
const multer = require('multer');
const { sendSMS, sendWhatsApp } = require('../services/twilioService');
const { validateRequest } = require('../middleware/requestValidation');
const { appointmentBookSchema, testNotifySchema, paymentVerifySchema } = require('../utils/routeSchemas');
const PendingPayment = require('../models/PendingPayment');
const PaymentLog = require('../models/PaymentLog');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const { encryptString, decryptString } = require('../utils/encryption');
const { encryptObject, decryptObject } = require('../utils/encryption');
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'rzp_test_placeholder'
});

const buildHealthIdCandidates = (rawHealthId) => {
    const input = String(rawHealthId || '').trim();
    const upper = input.toUpperCase();
    const candidates = new Set([input, upper]);

    if (/^\d{6}$/.test(input)) {
        candidates.add(`MC-${input}`);
    }

    const match = upper.match(/^MC-(\d{6})$/);
    if (match) {
        candidates.add(match[1]);
    }

    return Array.from(candidates).filter(Boolean);
};

const { requestOtpSession, verifyOtpSession } = require('../services/otpService');

// Verify that a Health ID exists before appointment booking
router.get('/verify-health/:healthId', async (req, res) => {
    try {
        const candidates = buildHealthIdCandidates(req.params.healthId);
        const card = await HealthCard.findOne({ healthId: { $in: candidates } })
            .select('healthId fullName mobile bloodGroup age gender aadhar')
            .lean();

        if (!card) {
            return res.status(404).json({ success: false, message: 'Health ID not found. Please generate health card first.' });
        }

        return res.json({ success: true, data: card });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Request OTP for Appointment Booking Health ID Verification
router.post('/request-otp', async (req, res) => {
    try {
        const { healthId } = req.body;
        if (!healthId) {
            return res.status(400).json({ success: false, message: 'Health Card ID is required.' });
        }

        const candidates = buildHealthIdCandidates(healthId);
        const card = await HealthCard.findOne({ healthId: { $in: candidates } }).lean();

        if (!card) {
            return res.status(404).json({ success: false, message: 'Health ID card not found. Please check card number.' });
        }

        if (!card.mobile) {
            return res.status(400).json({ success: false, message: 'No registered mobile number found for this Health ID.' });
        }

        const otpResult = await requestOtpSession({
            identifier: card.healthId,
            scope: 'appointment',
            mobile: card.mobile,
            metadata: {
                healthId: card.healthId,
                fullName: card.fullName,
                mobile: card.mobile,
                gender: card.gender,
                age: card.age,
                bloodGroup: card.bloodGroup,
                aadhar: card.aadhar
            }
        });

        if (otpResult.rateLimited) {
            return res.status(429).json({
                success: false,
                ...otpResult
            });
        }

        res.json({
            success: true,
            ...otpResult,
            healthId: card.healthId
        });
    } catch (error) {
        console.error('Appointment Request OTP Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Verify OTP for Appointment Booking
router.post('/verify-otp', async (req, res) => {
    try {
        const { sessionId, otp } = req.body;
        if (!sessionId || !otp) {
            return res.status(400).json({ success: false, message: 'Missing required parameters (sessionId, otp).' });
        }

        const verifyResult = await verifyOtpSession({
            sessionId,
            scope: 'appointment',
            otp
        });

        if (!verifyResult.success) {
            return res.status(400).json(verifyResult);
        }

        res.json({
            success: true,
            message: 'Health ID verified with OTP successfully!',
            accessToken: verifyResult.accessToken,
            data: verifyResult.metadata
        });
    } catch (error) {
        console.error('Appointment Verify OTP Error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ मेमोरी स्टोरेज सेटअप (फाइल फोल्डर में नहीं जाएगी)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB Limit
});

const { verifyAdmin, verifyAdminOrEmployee } = require('../middleware/auth');

// Route: Register & Upload to DB
router.post('/book', upload.single('healthCard'), validateRequest({ body: appointmentBookSchema }), async (req, res) => {
    try {
        const { 
            name, gender, age, aadhar, phone, bloodGroup, 
            healthId, street, city, pin, department, doctor, date, message, hospitalId,
            appointmentType
        } = req.body;

        if (!name || !aadhar || !phone || !healthId || !date || !hospitalId || !appointmentType) {
            return res.status(400).json({
                success: false,
                message: 'Required fields missing. Please select a hospital, fill all details, and select appointment type.'
            });
        }

        const validTypes = ['physical_visit', 'teleconsultation'];
        if (!validTypes.includes(appointmentType)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid appointment type selected.'
            });
        }

        const healthIdCandidates = buildHealthIdCandidates(healthId);
        const verifiedCard = await HealthCard.findOne({ healthId: { $in: healthIdCandidates } })
            .select('healthId fullName mobile')
            .lean();

        if (!verifiedCard) {
            return res.status(400).json({
                success: false,
                message: 'Health ID not verified. Please verify valid Health ID before booking appointment.'
            });
        }

        const partner = await HealthPartner.findOne({ uniqueId: hospitalId }).lean();
        if (!partner) {
            return res.status(400).json({ success: false, message: 'Invalid medical facility selected. Please choose a valid facility.' });
        }

        // If Physical Visit: book directly as before
        if (appointmentType === 'physical_visit') {
            const newAppointment = new Appointment({
                name, gender, age, aadhar, phone, bloodGroup,
                healthId: verifiedCard.healthId,
                street, city, pincode: pin,
                department,
                doctor: doctor || partner.businessName,
                hospitalId,
                hospitalName: partner.businessName,
                date,
                message,
                appointmentType,
                paymentStatus: 'Paid' // Free physical visit starts out as Paid/complete
            });

            // ✅ फाइल को डेटाबेस बफर में डालना
            if (req.file) {
                newAppointment.healthCardData = req.file.buffer;
                newAppointment.healthCardContentType = req.file.mimetype;
                newAppointment.healthCardFileName = req.file.originalname;
            }

            await newAppointment.save();

            // 🟢 Send SMS & WhatsApp Notification
            let notificationResults = null;
            const appointmentMsg = `Hello ${name}, your appointment (Physical Visit) with ${doctor || 'the doctor'} at ${department || 'the clinic'} on ${date} has been successfully requested. Thank you for choosing us!`;
            
            if (phone) {
                const [smsResult, waResult] = await Promise.all([
                    sendSMS(phone, appointmentMsg),
                    sendWhatsApp(phone, appointmentMsg)
                ]);
                notificationResults = {
                    sms: smsResult,
                    whatsapp: waResult
                };
                console.log('Appointment notification results:', {
                    phone,
                    sms: smsResult,
                    whatsapp: waResult
                });
            }

            const responsePayload = {
                success: true,
                message: "Registered Successfully in Database!",
                data: {
                    id: newAppointment._id,
                    name: newAppointment.name,
                    healthId: newAppointment.healthId,
                    phone: newAppointment.phone,
                    hospitalName: newAppointment.hospitalName,
                    date: newAppointment.date,
                    department: newAppointment.department,
                    doctor: newAppointment.doctor,
                    appointmentType: newAppointment.appointmentType,
                    createdAt: newAppointment.createdAt
                }
            };
            if (process.env.NODE_ENV !== 'production') {
                responsePayload.notificationResults = notificationResults;
            }

            return res.status(200).json(responsePayload);
        }

        // If Teleconsultation: initiate Razorpay payment process
        const pendingOrderId = 'APPT_' + Date.now() + '_' + Math.floor(Math.random() * 1000);

        const pendingData = {
            name, gender, age, aadhar, phone, bloodGroup,
            healthId: verifiedCard.healthId,
            street, city, pincode: pin,
            department,
            doctor: doctor || partner.businessName,
            hospitalId,
            hospitalName: partner.businessName,
            date,
            message,
            appointmentType
        };

        if (req.file) {
            // Store file buffer inside pendingData
            pendingData.healthCardData = req.file.buffer;
            pendingData.healthCardContentType = req.file.mimetype;
            pendingData.healthCardFileName = req.file.originalname;
        }

        await PendingPayment.create({
            orderId: pendingOrderId,
            paymentType: 'appointment',
            data:
            encryptString(JSON.stringify(pendingData))
        });

        const order = await razorpay.orders.create({
            amount: 20000, // 200 INR in paise
            currency: 'INR',
            receipt: pendingOrderId,
            notes: {
                paymentType: 'appointment',
                pendingOrderId: pendingOrderId,
                fullName: name,
                mobile: phone
            }
        });

        return res.json({
            success: true,
            requiresPayment: true,
            orderId: order.id,
            pendingOrderId: pendingOrderId,
            amount: order.amount,
            currency: order.currency,
            key: process.env.RAZORPAY_KEY_ID
        });

    } catch (error) {
        console.error("Booking Error:", error);
        res.status(500).json({ success: false, message: "Database Error: " + error.message });
    }
});

// Route: Verify Razorpay Payment for Teleconsultation Appointment
router.post('/verify-payment', validateRequest({ body: paymentVerifySchema }), async (req, res) => {
    try {
        const {
            razorpay_order_id,
            razorpay_payment_id,
            razorpay_signature,
            pendingOrderId
        } = req.body;

        const generatedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(`${razorpay_order_id}|${razorpay_payment_id}`)
            .digest('hex');

        if (generatedSignature !== razorpay_signature) {
            return res.status(400).json({ success: false, message: 'Payment signature verification failed' });
        }

        const pendingRecord = await PendingPayment.findOne({ 
            orderId: pendingOrderId,
            paymentType: 'appointment'
        });

        if (!pendingRecord) {
            console.error('No pending appointment found for order:', pendingOrderId);
            return res.status(404).json({ success: false, message: 'Pending appointment order not found' });
        }

     let pendingData;
     try{
        pendingData = typeof pendingRecord.data === 'string' ? JSON.parse(pendingRecord.data) : pendingRecord.data;

        if(
            !pendingData || typeof pendingData !== 'object' || Array.isArray(pendingData)
        ) {
            throw new Error('Invalid pending appointment data');
        }
        
     } catch (error) {
        console.error('pending appointment data decryption failed:', error. message);

        return res.status(500).json({
            success:false,
            message: 'Unable to process appointment data securely.'
        });
     }

        const newAppointment = new Appointment({
            name: pendingData.name,
            gender: pendingData.gender,
            age: pendingData.age,
            aadhar: pendingData.aadhar,
            phone: pendingData.phone,
            bloodGroup: pendingData.bloodGroup,
            healthId: pendingData.healthId,
            street: pendingData.street,
            city: pendingData.city,
            pincode: pendingData.pincode,
            department: pendingData.department,
            doctor: pendingData.doctor,
            hospitalId: pendingData.hospitalId,
            hospitalName: pendingData.hospitalName,
            date: pendingData.date,
            message: pendingData.message,
            appointmentType: pendingData.appointmentType,
            paymentId: razorpay_payment_id,
            orderId: pendingOrderId,
            paymentStatus: 'Paid'
        });

        if (pendingData.healthCardData) {
            let bufferData;
            if (Buffer.isBuffer(pendingData.healthCardData)) {
                bufferData = pendingData.healthCardData;
            } else if (pendingData.healthCardData.buffer) {
                bufferData = Buffer.from(pendingData.healthCardData.buffer);
            } else if (pendingData.healthCardData.data) {
                bufferData = Buffer.from(pendingData.healthCardData.data);
            } else if (typeof pendingData.healthCardData.value === 'function') {
                bufferData = pendingData.healthCardData.value();
            } else {
                bufferData = Buffer.from(pendingData.healthCardData);
            }
            newAppointment.healthCardData = bufferData;
            newAppointment.healthCardContentType = pendingData.healthCardContentType;
            newAppointment.healthCardFileName = pendingData.healthCardFileName;
        }

        await newAppointment.save();

        // 🟢 Send SMS & WhatsApp Notification
        let notificationResults = null;
        const appointmentMsg = `Hello ${pendingData.name}, your appointment (Teleconsultation) with ${pendingData.doctor || 'the doctor'} at ${pendingData.department || 'the clinic'} on ${pendingData.date} has been successfully requested. Thank you for choosing us!`;
        
        if (pendingData.phone) {
            const [smsResult, waResult] = await Promise.all([
                sendSMS(pendingData.phone, appointmentMsg),
                sendWhatsApp(pendingData.phone, appointmentMsg)
            ]);
            notificationResults = {
                sms: smsResult,
                whatsapp: waResult
            };
            console.log('Teleconsultation notification results:', {
                phone: pendingData.phone,
                sms: smsResult,
                whatsapp: waResult
            });
        }

        // Write to PaymentLog
        try {
            await PaymentLog.create({
                orderId: pendingOrderId,
                amount: '200',
                status: 'success',
                paymentId: razorpay_payment_id,
                transactionId: razorpay_order_id,
                schemeType: 'appointment',
                ipAddress: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent'),
                rawResponse: req.body,
                verificationStatus: 'verified',
                amountVerified: true,
                signatureVerified: true
            });
        } catch (logError) {
            console.warn('PaymentLog write failed (appointment):', logError.message);
        }

        // Clean up pending record from MongoDB
        await PendingPayment.deleteOne({ orderId: pendingOrderId });

        const responsePayload = {
            success: true,
            message: "Teleconsultation booked and payment verified successfully!",
            data: {
                id: newAppointment._id,
                name: newAppointment.name,
                healthId: newAppointment.healthId,
                phone: newAppointment.phone,
                hospitalName: newAppointment.hospitalName,
                date: newAppointment.date,
                department: newAppointment.department,
                doctor: newAppointment.doctor,
                appointmentType: newAppointment.appointmentType,
                paymentId: newAppointment.paymentId,
                orderId: newAppointment.orderId,
                paymentStatus: newAppointment.paymentStatus,
                createdAt: newAppointment.createdAt
            }
        };
        if (process.env.NODE_ENV !== 'production') {
            responsePayload.notificationResults = notificationResults;
        }

        res.status(200).json(responsePayload);
    } catch (error) {
        console.error("Verify Payment Error:", error);
        res.status(500).json({ success: false, message: "Database Error: " + error.message });
    }
});

// Route: फाइल देखने के लिए (ID के ज़रिये डेटाबेस से फाइल निकालना)
router.get('/view-card/:id', async (req, res) => {
    try {
        const patient = await Appointment.findById(req.params.id);
        if (!patient || !patient.healthCardData) return res.status(404).send("No file found");

        res.set('Content-Type', patient.healthCardContentType);
        res.send(patient.healthCardData);
    } catch (e) { res.status(500).send(e.message); }
});

// ✅ Route: Get All Appointments (For Admin Dashboard)
router.get('/all', verifyAdminOrEmployee, async (req, res) => {
    try {
        const appointments = await Appointment.find()
            .select('-healthCardData')
            .sort({ createdAt: -1 });
        res.json({ success: true, data: appointments });
    } catch (error) {
        console.error("Fetch Appointments Error:", error);
        res.status(500).json({ success: false, message: "Error fetching appointments" });
    }
});

// Debug route to validate SMS/WhatsApp delivery without booking flow
router.post('/test-notify', validateRequest({ body: testNotifySchema }), async (req, res) => {
    try {
        if (process.env.NODE_ENV === 'production') {
            return res.status(404).json({ success: false, message: 'Not found' });
        }

        const { phone, message, sendSms = true, sendWhatsapp = true } = req.body;

        if (!phone) {
            return res.status(400).json({ success: false, message: 'Phone is required' });
        }

        const text = message || 'Aagaj test notification from appointment system.';
        const results = {};

        if (sendSms) {
            const smsRes = await sendSMS(phone, text);
            results.sms = smsRes;
        }

        if (sendWhatsapp) {
            const waRes = await sendWhatsApp(phone, text);
            results.whatsapp = waRes;
        }

        return res.json({ success: true, message: 'Notification attempt completed', results });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

module.exports = router;
