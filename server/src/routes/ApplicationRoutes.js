const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const Razorpay = require('razorpay');
const { Applicant, NormalApplicant } = require('../models/ApplicationSchema');
const PendingPayment = require('../models/PendingPayment');

const { encryptString, decryptString } = require('../utils/encryption');

const PaymentLog = require('../models/PaymentLog');
const crypto = require('crypto');
const { sendApplicationConfirmation } = require('../services/emailService');
const { validateRequest } = require('../middleware/requestValidation');
const { jobApplicationCreateOrderSchema, paymentVerifySchema } = require('../utils/routeSchemas');


const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'rzp_test_placeholder'
});

const uploadDir = path.join(__dirname, '..', 'uploads');
try {
    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
    }
} catch (err) {
    console.warn('⚠️ Could not create application uploads directory in Vercel:', err.message);
}

const upload = require('../middleware/upload');

const handlePhotoUpload = (req, res, next) => {
    upload.single('photo')(req, res, (err) => {
        if (!err) {
            return next();
        }

        const isMulterError = err.name === 'MulterError' || (typeof multer !== 'undefined' && err instanceof multer.MulterError);
        return res.status(400).json({
            success: false,
            message: isMulterError
                ? (err.code === 'LIMIT_FILE_SIZE' ? 'Photo size must be less than or equal to 5MB.' : `Photo upload error: ${err.message}`)
                : (err.message || 'Photo upload failed.')
        });
    });
};

// Helper to fetch image buffer (checks local filesystem first, then falls back to production url)
async function getImageBuffer(photoPath) {
    if (!photoPath || typeof photoPath !== 'string') return null;

    // ✅ Handle absolute Cloudinary URLs directly
    if (photoPath.startsWith('http://') || photoPath.startsWith('https://')) {
        try {
            const response = await fetch(photoPath);
            if (response.ok) {
                const arrayBuffer = await response.arrayBuffer();
                return Buffer.from(arrayBuffer);
            }
        } catch (err) {
            console.error("Failed to fetch photo directly from URL:", photoPath, err.message);
        }
    }

    // Clean query parameters and hash if any
    const cleanPath = photoPath.split('?')[0].split('#')[0];
    const basename = path.basename(cleanPath);
    
    // Local directory candidates
    const localCandidates = [
        path.join(__dirname, '..', 'uploads', basename),
        path.join(__dirname, '..', '..', 'uploads', basename),
        path.join(__dirname, '..', cleanPath.replace(/^\/+/, '')),
        path.join(__dirname, '..', '..', cleanPath.replace(/^\/+/, ''))
    ];

    for (const localPath of localCandidates) {
        if (fs.existsSync(localPath)) {
            try {
                return fs.readFileSync(localPath);
            } catch (err) {
                console.error("Error reading local photo:", err);
            }
        }
    }

    // Fallback: Fetch from production server uploads folder
    const fallbackBaseUrl = process.env.PRODUCTION_FALLBACK_URL || 'https://www.aagajfoundation.com';
    const cleanFallbackBaseUrl = fallbackBaseUrl.replace(/\/+$/, '');

    const prodUrl = `${cleanFallbackBaseUrl}/uploads/${basename}`;
    try {
        const response = await fetch(prodUrl);
        if (response.ok) {
            const arrayBuffer = await response.arrayBuffer();
            return Buffer.from(arrayBuffer);
        }
    } catch (netErr) {
        console.error("Failed to fetch photo from production URL:", prodUrl, netErr.message);
    }

    // Secondary fallback URL: try clean path directly
    const prodUrlSecondary = `${cleanFallbackBaseUrl}/${cleanPath.replace(/^\/+/, '')}`;
    try {
        const response = await fetch(prodUrlSecondary);
        if (response.ok) {
            const arrayBuffer = await response.arrayBuffer();
            return Buffer.from(arrayBuffer);
        }
    } catch (netErr) {
        console.error("Failed to fetch photo from secondary production URL:", prodUrlSecondary, netErr.message);
    }

    return null;
}

// ✅ PROFESSIONAL PDF GENERATOR (With Async/Await & Education Details)
function generatePDF(applicant, stream) {
    return new Promise(async (resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 30, size: 'A4' });
            
            // ✅ FIX: PDF jab poori save ho jaye, tabhi aage badhe
            stream.on('finish', () => resolve(true));
            stream.on('error', (err) => reject(err));

            doc.pipe(stream);

            const pageWidth = doc.page.width;
            const left = 30;
            const right = pageWidth - 30;
            const contentWidth = right - left;
            const lineGap = 18;

            const safeText = (value, fallback = 'N/A') => {
                if (value === undefined || value === null) return fallback;
                const text = String(value).trim();
                return text ? text : fallback;
            };

            const formatDate = (value) => {
                const d = value ? new Date(value) : new Date();
                if (Number.isNaN(d.getTime())) return new Date().toDateString();
                return d.toDateString();
            };

            const drawSectionTitle = (title) => {
                const y = doc.y;
                doc.rect(left, y, contentWidth, 20).fill('#EEF3FB');
                doc.fillColor('#0B2C66').font('Helvetica-Bold').fontSize(11).text(title, left + 8, y + 6, {
                    width: contentWidth - 16,
                    align: 'left'
                });
                doc.fillColor('black');
                doc.y = y + 24;
            };

            const drawField = (x, y, label, value, width, options = {}) => {
                const labelWidth = options.labelWidth || 80;
                const valueOffset = labelWidth + 2;
                const valStr = safeText(value);
                const fontSize = options.fontSize || 9.5;
                
                doc.font('Helvetica-Bold').fontSize(fontSize).text(`${label}:`, x, y, { width: labelWidth, lineBreak: false });
                
                const valWidth = Math.max(20, width - valueOffset);
                doc.font('Helvetica').fontSize(fontSize);
                const textHeight = doc.heightOfString(valStr, { width: valWidth });
                
                doc.text(valStr, x + valueOffset, y, { width: valWidth });
                return textHeight;
            };

            // Header block
            doc.rect(left, 30, contentWidth, 74).fill('#0B2C66');
            doc.fillColor('white').font('Helvetica-Bold').fontSize(22).text('AAGAJ FOUNDATION', left, 45, {
                width: contentWidth,
                align: 'center'
            });
            doc.font('Helvetica').fontSize(10).text('Registered Under Indian Trust Act 1882', left, 73, {
                width: contentWidth,
                align: 'center'
            });
            doc.fillColor('#0B2C66').font('Helvetica-Bold').fontSize(13).text('EMPLOYEE APPLICATION FORM', left, 92, {
                width: contentWidth,
                align: 'center'
            });
            doc.fillColor('black');
            doc.y = 118;

            // Personal section with photo frame
            drawSectionTitle('PERSONAL INFORMATION');
            const personalTop = doc.y;
            const boxHeight = 150;
            doc.rect(left, personalTop, contentWidth, boxHeight).stroke('#D6DEEA');

            const photoFrameX = right - 100;
            const photoFrameY = personalTop + 10;
            const photoSizeW = 85;
            const photoSizeH = 105;
            doc.rect(photoFrameX, photoFrameY, photoSizeW, photoSizeH).stroke('#AAB8D1');
            doc.font('Helvetica').fontSize(8).fillColor('#6B7280').text('Applicant Photo', photoFrameX, photoFrameY + photoSizeH + 4, {
                width: photoSizeW,
                align: 'center'
            });
            doc.fillColor('black');

            const fallbackLogoPath = path.join(__dirname, '..', 'assets', 'logo.jpg');
            const photoBuffer = await getImageBuffer(applicant.photoPath || applicant.photoUrl || applicant.photo || applicant.image);
            const imageToDraw = photoBuffer || (fs.existsSync(fallbackLogoPath) ? fallbackLogoPath : null);
            
            if (imageToDraw) {
                try {
                    doc.image(imageToDraw, photoFrameX + 3, photoFrameY + 3, {
                        fit: [photoSizeW - 6, photoSizeH - 6],
                        align: 'center',
                        valign: 'center'
                    });
                } catch (e) {
                    console.log('PDF Photo Error:', e.message);
                }
            }

            const leftColX = left + 12;
            const rightColX = left + 230;
            const colWidthLeft = 210;
            const colWidthRight = 195;

            let currentYLeft = personalTop + 10;
            const leftFields = [
                { label: 'Application ID', value: `AF-${safeText(applicant.uniqueId, '--')}`, labelWidth: 85 },
                { label: 'Applied Post', value: applicant.roleApplied, labelWidth: 85 },
                { label: 'Full Name', value: applicant.fullName, labelWidth: 85 },
                { label: 'Mobile No', value: applicant.mobile, labelWidth: 85 },
                { label: 'Email ID', value: applicant.email, labelWidth: 85 },
                { label: 'Aadhar No', value: applicant.aadhar, labelWidth: 85 }
            ];

            leftFields.forEach(field => {
                const height = drawField(leftColX, currentYLeft, field.label, field.value, colWidthLeft, { labelWidth: field.labelWidth, fontSize: 9.5 });
                currentYLeft += Math.max(14, height) + 4;
            });

            let currentYRight = personalTop + 10;
            const rightFields = [
                { label: 'Date of Birth', value: applicant.dob, labelWidth: 80 },
                { label: 'District', value: applicant.district, labelWidth: 80 },
                { label: 'State', value: applicant.state, labelWidth: 80 },
                { label: 'Apply For', value: applicant.applyForPost || applicant.place, labelWidth: 80 },
                { label: 'Post Place', value: applicant.postPlace, labelWidth: 80 }
            ];

            rightFields.forEach(field => {
                const height = drawField(rightColX, currentYRight, field.label, field.value, colWidthRight, { labelWidth: field.labelWidth, fontSize: 9.5 });
                currentYRight += Math.max(14, height) + 4;
            });

            doc.y = personalTop + boxHeight + 8;

            // Education section in table format
            drawSectionTitle('EDUCATIONAL QUALIFICATIONS');
            const eduTop = doc.y;
            const tableCols = [110, 200, 85, 55, 70];
            const tableX = left;
            const headers = ['Qualification', 'School / College', 'Board / University', 'Year', 'Marks'];
            const q = applicant.qualifications || {};

            const eduRows = [
                ['Matriculation', safeText(q.matric && q.matric.school), safeText(q.matric && q.matric.board), safeText(q.matric && q.matric.year), safeText(q.matric && q.matric.marks, 'N/A')],
                ['Intermediate', safeText(q.inter && q.inter.school), safeText(q.inter && q.inter.board), safeText(q.inter && q.inter.year), safeText(q.inter && q.inter.marks, 'N/A')],
                ['Graduation', safeText(q.grad && q.grad.school), safeText(q.grad && q.grad.board), safeText(q.grad && q.grad.year), safeText(q.grad && q.grad.marks, 'N/A')]
            ];

            const headerY = eduTop;
            doc.rect(tableX, headerY, contentWidth, 22).fill('#E6EDF9');
            let runningX = tableX;
            headers.forEach((h, i) => {
                doc.fillColor('#0B2C66').font('Helvetica-Bold').fontSize(9).text(h, runningX + 4, headerY + 7, {
                    width: tableCols[i] - 8,
                    align: 'left',
                    lineBreak: false
                });
                runningX += tableCols[i];
                if (i < tableCols.length - 1) {
                    doc.moveTo(runningX, headerY).lineTo(runningX, headerY + 22).stroke('#C4D0E5');
                }
            });

            let rowY = headerY + 22;
            eduRows.forEach((row) => {
                let maxCellHeight = 26; // Minimum cell height
                row.forEach((val, idx) => {
                    doc.font('Helvetica').fontSize(9);
                    const cellWidth = tableCols[idx] - 8;
                    const cellHeight = doc.heightOfString(String(val), { width: cellWidth });
                    const totalHeight = cellHeight + 16;
                    if (totalHeight > maxCellHeight) {
                        maxCellHeight = totalHeight;
                    }
                });

                doc.rect(tableX, rowY, contentWidth, maxCellHeight).stroke('#D6DEEA');
                let colX = tableX;
                row.forEach((val, idx) => {
                    doc.fillColor('black').font('Helvetica').fontSize(9).text(String(val), colX + 4, rowY + 8, {
                        width: tableCols[idx] - 8,
                        align: 'left'
                    });
                    colX += tableCols[idx];
                    if (idx < tableCols.length - 1) {
                        doc.moveTo(colX, rowY).lineTo(colX, rowY + maxCellHeight).stroke('#D6DEEA');
                    }
                });
                rowY += maxCellHeight;
            });

            doc.y = rowY + 8;

            // Payment section
            drawSectionTitle('PAYMENT DETAILS');
            const paymentTop = doc.y;
            doc.rect(left, paymentTop, contentWidth, 78).stroke('#D6DEEA');

            const applicationDate = formatDate(applicant.date);
            drawField(left + 12, paymentTop + 14, 'Transaction ID', applicant.paymentId, contentWidth - 24, { labelWidth: 112 });
            drawField(left + 12, paymentTop + 14 + lineGap, 'Amount Paid', `Rs. ${safeText(applicant.amount, '0')}`, contentWidth - 24, { labelWidth: 112 });
            drawField(left + 12, paymentTop + 14 + lineGap * 2, 'Date of Application', applicationDate, contentWidth - 24, { labelWidth: 112 });

            doc.y = paymentTop + 86;

            // Declaration and signature blocks
            drawSectionTitle('DECLARATION');
            doc.rect(left, doc.y, contentWidth, 54).stroke('#D6DEEA');
            doc.font('Helvetica').fontSize(10).text(
                'I hereby declare that the information provided above is true to the best of my knowledge and belief.',
                left + 10,
                doc.y + 12,
                { width: contentWidth - 20, align: 'left' }
            );

            const signY = doc.y + 40;
            doc.moveTo(left + 18, signY + 15).lineTo(left + 180, signY + 15).stroke('#555');
            doc.moveTo(right - 180, signY + 15).lineTo(right - 18, signY + 15).stroke('#555');
            doc.font('Helvetica').fontSize(9).text('Authorized Signatory', left + 18, signY + 20, { width: 162, align: 'center' });
            doc.font('Helvetica').fontSize(9).text('Applicant Signature', right - 180, signY + 20, { width: 162, align: 'center' });

            // Footer note
            doc.font('Helvetica').fontSize(8).fillColor('#4B5563').text(
                `Generated on ${new Date().toLocaleString('en-IN')} | Aagaj Foundation`,
                left,
                doc.page.height - 40,
                { width: contentWidth, align: 'center' }
            );
            doc.fillColor('black');
            
            doc.end();
        } catch (error) {
            reject(error);
        }
    });
}

async function finalizeApplicationSubmission({
    appData,
    paymentId,
    orderId,
    paymentStatus = 'success',
    transactionId,
    ipAddress,
    userAgent,
    rawResponse
}) {
    const SaveModel = appData.job_category === 'Normal' ? NormalApplicant : Applicant;
    const newApplicant = new SaveModel({
        ...appData,
        status: 'Success',
        paymentId,
        applicationPdf: ''
    });

    await newApplicant.save();

    const pdfPath = `/api/application/pdf/${newApplicant._id}`;
    await SaveModel.findByIdAndUpdate(newApplicant._id, { applicationPdf: pdfPath });
    const pdfGenerated = true;

    try {
        await sendApplicationConfirmation(appData);
    } catch (mailError) {
        console.warn('Application confirmation email failed:', mailError.message);
    }

    try {
        await PaymentLog.create({
            orderId: orderId,
            amount: appData.amount,
            status: paymentStatus,
            paymentId: paymentId,
            transactionId: transactionId || orderId,
            schemeType: 'application',
            ipAddress,
            userAgent,
            rawResponse,
            verificationStatus: 'verified',
            amountVerified: true,
            signatureVerified: true
        });
    } catch (logError) {
        console.warn('PaymentLog write failed (application):', logError.message);
    }

    const redirectUrl = `/application.html?status=success&txn=${paymentId}&name=${encodeURIComponent(appData.fullName)}&mobile=${appData.mobile}&email=${encodeURIComponent(appData.email)}&aadhar=${appData.aadhar}&unique_id=${appData.uniqueId}&dob=${appData.dob}&district=${encodeURIComponent(appData.district)}&state=${encodeURIComponent(appData.state)}&apply_for_post=${encodeURIComponent(appData.applyForPost || appData.place || '')}&role=${encodeURIComponent(appData.roleApplied)}&amount=${appData.amount}&photo=${encodeURIComponent(appData.photoPath || '')}&pdf=${encodeURIComponent(pdfPath)}&post_place=${encodeURIComponent(appData.postPlace || '')}&doj=${encodeURIComponent(new Date(appData.date || Date.now()).toLocaleDateString('en-GB'))}`;

    return { success: true, redirectUrl, pdfPath };
}

function resolvePublicUploadFile(publicPath) {
    if (!publicPath || typeof publicPath !== 'string') return null;

    const relativePath = publicPath.startsWith('/') ? publicPath.substring(1) : publicPath;
    const backendFile = path.join(__dirname, '..', relativePath);
    if (fs.existsSync(backendFile)) {
        return publicPath.startsWith('/') ? publicPath : `/${publicPath}`;
    }

    const legacyFile = path.join(__dirname, '..', '..', relativePath);
    if (fs.existsSync(legacyFile)) {
        const fileName = path.basename(relativePath);
        return `/uploads/${fileName}`;
    }

    return null;
}

async function ensureApplicantPdf(applicant, model, forceRegenerate = false) {
    const existingPdfPath = resolvePublicUploadFile(applicant.applicationPdf);
    if (existingPdfPath && !forceRegenerate) {
        return existingPdfPath;
    }

    const safeId = (applicant.uniqueId || String(applicant._id || Date.now())).replace(/[^a-zA-Z0-9_-]/g, '_');
    const pdfName = `APP_AF${safeId}_${Date.now()}.pdf`;
    const newPdfPath = `/uploads/${pdfName}`;

    await generatePDF(applicant, pdfName);
    await model.findByIdAndUpdate(applicant._id, { applicationPdf: newPdfPath });
    return newPdfPath;
}
// ✅ 1. CREATE ORDER - Store data temporarily, don't save to DB yet
router.post('/create-order', handlePhotoUpload, validateRequest({ body: jobApplicationCreateOrderSchema }), async (req, res) => {
    try {
        if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
            console.error("RAZORPAY configuration missing in .env file");
            return res.status(500).json({ success: false, message: "Payment gateway not configured. Please contact administrator." });
        }

        const {
            full_name,
            email,
            mobile,
            dob,
            district,
            state,
            block,
            panchayat,
            place,
            apply_for_post,
            role_applied,
            qualifications,
            amount,
            aadhar,
            job_category,
            registeredBy,
            post_place
        } = req.body;
        const orderId = "APP" + Date.now();
        let TargetModel = job_category === 'Normal' ? NormalApplicant : Applicant;
        
        // // ✅ BUG FIX: Safe Unique ID Generator
        // const lastApplicant = await TargetModel.findOne().sort({ _id: -1 });
        // let nextId = "0001";
        // if (lastApplicant && lastApplicant.uniqueId) { 
        //     const lastNum = parseInt(lastApplicant.uniqueId.replace(/\D/g, ''));
        //     if (!isNaN(lastNum)) {
        //         nextId = (lastNum + 1).toString().padStart(4, '0'); 
        //     }
        // }


        // ✅ BUG FIX: Category & Year-Wise Unique ID Generator (NGO-YY-XXXX or NOR-YY-XXXX)
        const currentYear = new Date().getFullYear().toString().slice(-2); // Gets "26" for 2026
        const idPrefix = job_category === 'Normal' ? 'NOR' : 'NGO'; // Prefix set karna
        
        // Find the last applicant created in the CURRENT year with this prefix
        const lastApplicant = await TargetModel.findOne({ 
            uniqueId: new RegExp(`^${idPrefix}-${currentYear}-`) 
        }).sort({ _id: -1 });

        let nextId = `${idPrefix}-${currentYear}-0001`; // Default: e.g. "NGO-26-0001" or "NOR-26-0001"

        if (lastApplicant && lastApplicant.uniqueId) { 
            // Split the ID (e.g., "NGO-26-0045" becomes ["NGO", "26", "0045"])
            const parts = lastApplicant.uniqueId.split('-');
            
            if (parts.length === 3 && parts[0] === idPrefix && parts[1] === currentYear) {
                const lastNum = parseInt(parts[2], 10);
                if (!isNaN(lastNum)) {
                    // Increment and pad with leading zeros to maintain 4 digits
                    nextId = `${idPrefix}-${currentYear}-${(lastNum + 1).toString().padStart(4, '0')}`; 
                }
            }
        }

        let qualParsed = {}; 
        try { qualParsed = qualifications ? JSON.parse(qualifications) : {}; } catch(e) { console.error("Parse error"); }

        // ✅ Create applicant object BUT DON'T SAVE to DB yet
        const newApplicant = new TargetModel({
            uniqueId: nextId, 
            orderId: orderId, 
            status: 'Pending',
            fullName: full_name, 
            email: email, 
            mobile: mobile, 
            dob: dob, 
            district: district, 
            state: state, 
            block: block || '',
            panchayat: panchayat || '',
            place: place || '',
            applyForPost: apply_for_post,
            aadhar: aadhar, 
            roleApplied: role_applied,
            job_category: job_category || 'NGO',
            photoPath: req.file ? req.file.path : '',
            applicationPdf: '',
            qualifications: qualParsed,
            amount: amount ? parseInt(amount) : 499,
            emp_username: email,
            registeredBy: registeredBy || 'Self',
            postPlace: post_place || ''
        });
        
        // ⚠️ DON'T SAVE YET - Only save after payment success
        console.log("Application prepared (NOT saved to DB yet):", orderId);
        console.log("Applicant Data:", newApplicant);

        // ✅ Store applicant data in MongoDB (TTL 60 minutes)
        try {
            const appData = newApplicant.toObject ? newApplicant.toObject() : newApplicant;
            await PendingPayment.create({
                orderId: orderId,
                paymentType: 'application',
                data: 
                encryptString(JSON.stringify(appData))
            });
            console.log("✅ Applicant stored in MongoDB pending collection");
        } catch (storeError) {
            console.error("❌ Error storing applicant in MongoDB:", storeError);
            return res.status(500).json({ success: false, message: "Failed to store payment data" });
        }

        const razorpayOrder = await razorpay.orders.create({
            amount: parseInt(newApplicant.amount, 10) * 100,
            currency: 'INR',
            receipt: orderId,
            notes: {
                paymentType: 'application',
                pendingOrderId: orderId,
                applicantName: full_name || '',
                applicantMobile: mobile || '',
                roleApplied: role_applied || ''
            }
        });

        return res.status(200).json({
            success: true,
            orderId: razorpayOrder.id,
            pendingOrderId: orderId,
            amount: razorpayOrder.amount,
            currency: razorpayOrder.currency,
            key: process.env.RAZORPAY_KEY_ID
        });

    } catch (error) {
        console.error("Create Order Error:", error);
        console.error("Error Stack:", error.stack);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ 2. VERIFY RAZORPAY PAYMENT & SAVE DATA ONLY ON SUCCESS
router.post('/verify-payment', validateRequest({ body: paymentVerifySchema }), async (req, res) => {
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

        const pendingRecord = await PendingPayment.findOne({
            orderId: pendingOrderId,
            paymentType: 'application'
        });

        if (!pendingRecord) {
            return res.status(404).json({ success: false, message: 'Pending application not found' });
        }

        let pendingAppData;

        try {
            pendingAppData = typeof pendingRecord.data === 'string' ? JSON.parse(decryptString(pendingRecord.data))
            : pendingRecord.data; 
        } catch (decryptError) {
            console.error(
                'Application data decryption failed:' ,
                decryptError.message
            );

            return res.status(500).json({
                success:false,
                message: 'unable to process application data securely.'
            });
        }

        const appData = {
            ...pendingAppData,
            status: 'success',
            paymentId: razorpay_payment_id,
            applicationPdf: ''
        };

        const result = await finalizeApplicationSubmission({
            appData,
            paymentId: razorpay_payment_id,
            orderId: pendingOrderId,
            paymentStatus: 'success',
            transactionId: razorpay_order_id,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            rawResponse: req.body
        });

        await PendingPayment.deleteOne({ orderId: pendingOrderId });

        return res.json(result);
    } catch (error) {
        console.error("Verify Error:", error);
        return res.status(500).json({ success: false, message: 'Payment verification failed' });
    }
});

// Open applicant PDF from admin dashboard (generates on-the-fly and streams directly)
router.get('/pdf/:id', async (req, res) => {
    try {
        const { id } = req.params;
        let applicant = await Applicant.findById(id).lean();

        if (!applicant) {
            applicant = await NormalApplicant.findById(id).lean();
        }

        if (!applicant) {
            return res.status(404).send('Applicant not found');
        }

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="APP_AF${applicant.uniqueId || id}.pdf"`);

        await generatePDF(applicant, res);
    } catch (error) {
        console.error('Applicant PDF open error:', error);
        if (!res.headersSent) {
            return res.status(500).send('Unable to open PDF right now');
        }
    }
});

const { verifyAdmin } = require('../middleware/auth');

// Route for admin to directly generate a candidate pass (payment bypass, custom roles & fee)
router.post('/admin/create', verifyAdmin, handlePhotoUpload, async (req, res) => {
    try {
        const {
            full_name,
            email,
            mobile,
            dob,
            district,
            state,
            block,
            panchayat,
            place,
            apply_for_post,
            role_applied,
            qualifications,
            amount,
            aadhar,
            job_category,
            registeredBy,
            post_place
        } = req.body;

        // Validation for critical fields
        if (!full_name || !email || !mobile || !dob || !district || !state || !apply_for_post || !role_applied || !aadhar) {
            return res.status(400).json({ success: false, message: "Required fields are missing." });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: "Candidate photo is required to generate card." });
        }

        const TargetModel = job_category === 'Normal' ? NormalApplicant : Applicant;

        // Year-and-category-wise unique ID generation
        const currentYear = new Date().getFullYear().toString().slice(-2);
        const idPrefix = job_category === 'Normal' ? 'NOR' : 'NGO';
        
        const lastApplicant = await TargetModel.findOne({ 
            uniqueId: new RegExp(`^${idPrefix}-${currentYear}-`) 
        }).sort({ _id: -1 });

        let nextId = `${idPrefix}-${currentYear}-0001`;

        if (lastApplicant && lastApplicant.uniqueId) { 
            const parts = lastApplicant.uniqueId.split('-');
            if (parts.length === 3 && parts[0] === idPrefix && parts[1] === currentYear) {
                const lastNum = parseInt(parts[2], 10);
                if (!isNaN(lastNum)) {
                    nextId = `${idPrefix}-${currentYear}-${(lastNum + 1).toString().padStart(4, '0')}`; 
                }
            }
        }

        let qualParsed = {}; 
        try { 
            qualParsed = qualifications ? (typeof qualifications === 'string' ? JSON.parse(qualifications) : qualifications) : {}; 
        } catch(e) { 
            console.error("Qualifications parse error", e); 
        }

        const mockPaymentId = "OFFLINE_AD_" + Date.now();
        const mockOrderId = "ADMIN_" + Date.now();

        const appData = {
            uniqueId: nextId, 
            orderId: mockOrderId, 
            status: 'Success',
            fullName: full_name, 
            email: email, 
            mobile: mobile, 
            dob: dob, 
            district: district, 
            state: state, 
            block: block || '',
            panchayat: panchayat || '',
            place: place || '',
            applyForPost: apply_for_post,
            aadhar: aadhar, 
            roleApplied: role_applied,
            job_category: job_category || 'NGO',
            photoPath: req.file ? req.file.path : '',
            applicationPdf: '',
            qualifications: qualParsed,
            amount: amount ? parseInt(amount, 10) : 499,
            emp_username: email,
            registeredBy: registeredBy || req.user?.email || 'Admin',
            postPlace: post_place || ''
        };

        const result = await finalizeApplicationSubmission({
            appData,
            paymentId: mockPaymentId,
            orderId: mockOrderId,
            paymentStatus: 'success',
            transactionId: mockOrderId,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            rawResponse: { type: 'admin_direct_creation', admin: req.user?.email }
        });

        // Fetch saved document to send back complete entity
        const savedApplicant = await TargetModel.findOne({ uniqueId: nextId });

        return res.status(200).json({
            success: true,
            message: "Custom job application card generated successfully!",
            data: savedApplicant,
            redirectUrl: result.redirectUrl,
            pdfPath: result.pdfPath
        });

    } catch (error) {
        console.error("Admin Direct Candidate Register Error:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Public status verification route
router.get('/status/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;
        // Search in both NGO jobs and normal jobs applicants
        let applicant = await Applicant.findOne({ uniqueId: uniqueId });
        if (!applicant) {
            applicant = await NormalApplicant.findOne({ uniqueId: uniqueId });
        }
        
        if (!applicant) {
            return res.status(404).json({ success: false, message: "Employee not found" });
        }

        res.json({ 
            success: true, 
            isActive: applicant.isActive !== false // defaults to true
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

module.exports = router;
