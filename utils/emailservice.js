// utils/emailService.js
const nodemailer = require('nodemailer');
const logger = require('./logger');

const transporter = nodemailer.createTransporter({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const emailTemplates = {
  welcome: {
    subject: 'Welcome to Raw Wealthy - Start Your Investment Journey',
    template: (context) => `
      <h1>Welcome to Raw Wealthy, ${context.name}!</h1>
      <p>Your account has been successfully created. Start investing in raw materials and grow your wealth.</p>
      <p><strong>Account Details:</strong></p>
      <ul>
        <li>Email: ${context.email}</li>
        <li>Referral Code: ${context.referralCode}</li>
      </ul>
      <a href="${process.env.CLIENT_URL}/dashboard" style="background: #fbbf24; color: #0f172a; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Go to Dashboard</a>
    `
  },
  kyc_submitted: {
    subject: 'KYC Application Received - Raw Wealthy',
    template: (context) => `
      <h1>KYC Application Received</h1>
      <p>Dear ${context.name},</p>
      <p>We have received your KYC application and it is currently under review.</p>
      <p>Application ID: <strong>${context.kycId}</strong></p>
      <p>We will notify you once the review is complete. This usually takes 24-48 hours.</p>
    `
  },
  kyc_approved: {
    subject: 'KYC Application Approved - Raw Wealthy',
    template: (context) => `
      <h1>KYC Application Approved! 🎉</h1>
      <p>Dear ${context.name},</p>
      <p>Your KYC application has been approved successfully.</p>
      <p>You now have full access to all investment features on our platform.</p>
      <a href="${process.env.CLIENT_URL}/investment-plans" style="background: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Start Investing</a>
    `
  },
  ticket_created: {
    subject: 'Support Ticket Created - Raw Wealthy',
    template: (context) => `
      <h1>Support Ticket Created</h1>
      <p>Dear ${context.name},</p>
      <p>Your support ticket has been created successfully.</p>
      <p><strong>Ticket Details:</strong></p>
      <ul>
        <li>Ticket ID: ${context.ticketId}</li>
        <li>Subject: ${context.subject}</li>
      </ul>
      <p>Our support team will get back to you within 24 hours.</p>
    `
  },
  ticket_reply: {
    subject: 'New Reply on Support Ticket - Raw Wealthy',
    template: (context) => `
      <h1>New Reply on Support Ticket</h1>
      <p>Dear ${context.name},</p>
      <p>You have received a new reply on your support ticket.</p>
      <p><strong>Ticket Details:</strong></p>
      <ul>
        <li>Ticket ID: ${context.ticketId}</li>
        <li>Subject: ${context.subject}</li>
      </ul>
      <a href="${process.env.CLIENT_URL}/support/tickets/${context.ticketId}" style="background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">View Ticket</a>
    `
  }
};

exports.sendEmail = async ({ to, subject, template, context }) => {
  try {
    if (!emailTemplates[template]) {
      throw new Error(`Email template '${template}' not found`);
    }

    const emailTemplate = emailTemplates[template];
    const html = emailTemplate.template(context);

    const mailOptions = {
      from: `"Raw Wealthy" <${process.env.EMAIL_USER}>`,
      to,
      subject: emailTemplate.subject || subject,
      html
    };

    const result = await transporter.sendMail(mailOptions);
    logger.info(`Email sent to ${to}: ${result.messageId}`);
    return result;
  } catch (error) {
    logger.error('Email sending failed:', error);
    throw error;
  }
};

exports.sendPasswordResetEmail = async (email, resetToken) => {
  const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;
  
  return this.sendEmail({
    to: email,
    subject: 'Password Reset Request - Raw Wealthy',
    template: 'password_reset',
    context: { resetUrl }
  });
};
