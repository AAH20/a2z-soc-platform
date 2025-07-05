const nodemailer = require('nodemailer');
const handlebars = require('handlebars');
const fs = require('fs').promises;
const path = require('path');

class EmailService {
  constructor() {
    this.transporter = null;
    this.templates = new Map();
    this.initializeTransporter();
    this.loadTemplates();
  }

  initializeTransporter() {
    if (process.env.SMTP_HOST) {
      this.transporter = nodemailer.createTransporter({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
    } else {
      console.warn('SMTP configuration not found. Email service will not function.');
    }
  }

  async loadTemplates() {
    const templates = [
      'welcome',
      'email-verification',
      'password-reset',
      'invitation',
      'subscription-welcome',
      'subscription-canceled',
      'payment-failed',
      'usage-warning',
      'security-alert',
      'monthly-report'
    ];

    for (const templateName of templates) {
      try {
        const templateContent = this.getDefaultTemplate(templateName);
        const compiled = handlebars.compile(templateContent);
        this.templates.set(templateName, compiled);
      } catch (error) {
        console.warn(`Failed to load email template ${templateName}:`, error.message);
      }
    }
  }

  // Send Welcome Email
  async sendWelcomeEmail(user, verificationToken) {
    const template = this.templates.get('welcome');
    if (!template) {
      throw new Error('Welcome email template not found');
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    const html = template({
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      verificationUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Welcome to A2Z SOC - Verify Your Email',
      html
    });
  }

  // Send Email Verification
  async sendEmailVerification(user, verificationToken) {
    const template = this.templates.get('email-verification');
    if (!template) {
      throw new Error('Email verification template not found');
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    const html = template({
      firstName: user.first_name,
      verificationUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Verify Your Email Address - A2Z SOC',
      html
    });
  }

  // Send Password Reset Email
  async sendPasswordResetEmail(user, resetToken) {
    const template = this.templates.get('password-reset');
    if (!template) {
      throw new Error('Password reset template not found');
    }

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    
    const html = template({
      firstName: user.first_name,
      resetUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Reset Your Password - A2Z SOC',
      html
    });
  }

  // Send Team Invitation Email
  async sendInvitationEmail(user, inviterName, organizationName, invitationToken) {
    const template = this.templates.get('invitation');
    if (!template) {
      throw new Error('Invitation template not found');
    }

    const invitationUrl = `${process.env.FRONTEND_URL}/accept-invitation?token=${invitationToken}`;
    
    const html = template({
      firstName: user.first_name,
      lastName: user.last_name,
      inviterName,
      organizationName,
      invitationUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: `You've been invited to join ${organizationName} on A2Z SOC`,
      html
    });
  }

  // Send Subscription Welcome Email
  async sendSubscriptionWelcomeEmail(user, planName, tenantName) {
    const template = this.templates.get('subscription-welcome');
    if (!template) {
      throw new Error('Subscription welcome template not found');
    }

    const dashboardUrl = `${process.env.FRONTEND_URL}/dashboard`;
    
    const html = template({
      firstName: user.first_name,
      planName,
      tenantName,
      dashboardUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: `Welcome to A2Z SOC ${planName} Plan!`,
      html
    });
  }

  // Send Subscription Canceled Email
  async sendSubscriptionCanceledEmail(user, planName, cancellationDate) {
    const template = this.templates.get('subscription-canceled');
    if (!template) {
      throw new Error('Subscription canceled template not found');
    }

    const html = template({
      firstName: user.first_name,
      planName,
      cancellationDate: new Date(cancellationDate).toLocaleDateString(),
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Your A2Z SOC subscription has been canceled',
      html
    });
  }

  // Send Payment Failed Email
  async sendPaymentFailedEmail(user, amount, nextRetryDate) {
    const template = this.templates.get('payment-failed');
    if (!template) {
      throw new Error('Payment failed template not found');
    }

    const billingUrl = `${process.env.FRONTEND_URL}/billing`;
    
    const html = template({
      firstName: user.first_name,
      amount: `$${(amount / 100).toFixed(2)}`,
      nextRetryDate: new Date(nextRetryDate).toLocaleDateString(),
      billingUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Payment Failed - Action Required',
      html
    });
  }

  // Send Usage Warning Email
  async sendUsageWarningEmail(user, usageType, percentageUsed, limit) {
    const template = this.templates.get('usage-warning');
    if (!template) {
      throw new Error('Usage warning template not found');
    }

    const billingUrl = `${process.env.FRONTEND_URL}/billing`;
    
    const html = template({
      firstName: user.first_name,
      usageType,
      percentageUsed: Math.round(percentageUsed),
      limit,
      billingUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: `Usage Warning: ${usageType} at ${Math.round(percentageUsed)}%`,
      html
    });
  }

  // Send Security Alert Email
  async sendSecurityAlertEmail(user, alertType, alertDetails) {
    const template = this.templates.get('security-alert');
    if (!template) {
      throw new Error('Security alert template not found');
    }

    const dashboardUrl = `${process.env.FRONTEND_URL}/dashboard`;
    
    const html = template({
      firstName: user.first_name,
      alertType,
      alertDetails,
      timestamp: new Date().toLocaleString(),
      dashboardUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: `Security Alert: ${alertType}`,
      html
    });
  }

  // Send Monthly Report Email
  async sendMonthlyReportEmail(user, reportData) {
    const template = this.templates.get('monthly-report');
    if (!template) {
      throw new Error('Monthly report template not found');
    }

    const dashboardUrl = `${process.env.FRONTEND_URL}/dashboard`;
    
    const html = template({
      firstName: user.first_name,
      month: new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric' }),
      totalAlerts: reportData.totalAlerts || 0,
      threatsBlocked: reportData.threatsBlocked || 0,
      complianceScore: reportData.complianceScore || 0,
      apiUsage: reportData.apiUsage || 0,
      dashboardUrl,
      companyName: 'A2Z SOC',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@a2zsoc.com'
    });

    return await this.sendEmail({
      to: user.email,
      subject: 'Your Monthly Security Report - A2Z SOC',
      html
    });
  }

  // Generic send email method
  async sendEmail({ to, subject, html, text }) {
    if (!this.transporter) {
      console.log('Email would be sent to:', to, 'Subject:', subject);
      return { messageId: 'test-' + Date.now() };
    }

    try {
      const info = await this.transporter.sendMail({
        from: `${process.env.FROM_NAME || 'A2Z SOC'} <${process.env.FROM_EMAIL}>`,
        to,
        subject,
        html,
        text: text || this.extractTextFromHtml(html)
      });

      console.log('Email sent successfully:', info.messageId);
      return info;
    } catch (error) {
      console.error('Failed to send email:', error);
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }

  // Extract text from HTML for fallback
  extractTextFromHtml(html) {
    return html
      .replace(/<[^>]*>/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // Default email templates
  getDefaultTemplate(templateName) {
    const templates = {
      'welcome': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Welcome to {{companyName}}</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to {{companyName}}!</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>Welcome to A2Z SOC! We're excited to have you join our AI-powered security operations platform.</p>
              <p>To get started, please verify your email address by clicking the button below:</p>
              <p style="text-align: center;">
                <a href="{{verificationUrl}}" class="button">Verify Email Address</a>
              </p>
              <p>Once verified, you'll have access to:</p>
              <ul>
                <li>AI-powered threat detection and analysis</li>
                <li>Real-time security monitoring</li>
                <li>Compliance reporting and auditing</li>
                <li>Cloud infrastructure discovery</li>
                <li>24/7 security operations center</li>
              </ul>
              <p>If you have any questions, feel free to reach out to our support team.</p>
            </div>
            <div class="footer">
              <p>Best regards,<br>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'email-verification': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Verify Your Email</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Verify Your Email</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>Please verify your email address to complete your account setup.</p>
              <p style="text-align: center;">
                <a href="{{verificationUrl}}" class="button">Verify Email Address</a>
              </p>
              <p>This link will expire in 24 hours. If you didn't create an account, you can safely ignore this email.</p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'password-reset': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Reset Your Password</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Reset Your Password</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>We received a request to reset your password. Click the button below to create a new password:</p>
              <p style="text-align: center;">
                <a href="{{resetUrl}}" class="button">Reset Password</a>
              </p>
              <p>This link will expire in 1 hour. If you didn't request this reset, you can safely ignore this email.</p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'invitation': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>You're Invited!</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>You're Invited to Join {{organizationName}}!</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>{{inviterName}} has invited you to join {{organizationName}} on {{companyName}}.</p>
              <p>{{companyName}} is an AI-powered security operations platform that provides comprehensive threat detection, monitoring, and compliance management.</p>
              <p style="text-align: center;">
                <a href="{{invitationUrl}}" class="button">Accept Invitation</a>
              </p>
              <p>This invitation will expire in 7 days.</p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'subscription-welcome': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Welcome to {{planName}}!</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #10b981; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #10b981; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to {{planName}}!</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>Congratulations! {{tenantName}} is now on the {{planName}} plan.</p>
              <p>You now have access to premium features including:</p>
              <ul>
                <li>Advanced AI threat detection</li>
                <li>Priority support</li>
                <li>Extended compliance reporting</li>
                <li>Enhanced API access</li>
                <li>Custom integrations</li>
              </ul>
              <p style="text-align: center;">
                <a href="{{dashboardUrl}}" class="button">Go to Dashboard</a>
              </p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'subscription-canceled': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Subscription Canceled</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #ef4444; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Subscription Canceled</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>Your {{planName}} subscription has been canceled and will end on {{cancellationDate}}.</p>
              <p>Until then, you'll continue to have access to all premium features.</p>
              <p>We're sorry to see you go! If you have any feedback or would like to reactivate your subscription, please don't hesitate to reach out.</p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'payment-failed': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Payment Failed</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #f59e0b; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #f59e0b; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Payment Failed</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>We couldn't process your payment of {{amount}}. This could be due to:</p>
              <ul>
                <li>Insufficient funds</li>
                <li>Expired card</li>
                <li>Bank declined the transaction</li>
              </ul>
              <p>We'll retry the payment on {{nextRetryDate}}. Please update your payment method to avoid service interruption.</p>
              <p style="text-align: center;">
                <a href="{{billingUrl}}" class="button">Update Payment Method</a>
              </p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'usage-warning': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Usage Warning</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #f59e0b; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #f59e0b; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Usage Warning</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>You've used {{percentageUsed}}% of your {{usageType}} limit ({{limit}}).</p>
              <p>To avoid service interruption, consider upgrading your plan or optimizing your usage.</p>
              <p style="text-align: center;">
                <a href="{{billingUrl}}" class="button">Manage Billing</a>
              </p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'security-alert': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Security Alert</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #ef4444; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background: #ef4444; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Security Alert</h1>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>We detected a security event that requires your attention:</p>
              <p><strong>Alert Type:</strong> {{alertType}}</p>
              <p><strong>Details:</strong> {{alertDetails}}</p>
              <p><strong>Time:</strong> {{timestamp}}</p>
              <p>Please review this alert in your dashboard and take appropriate action.</p>
              <p style="text-align: center;">
                <a href="{{dashboardUrl}}" class="button">View Dashboard</a>
              </p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `,

      'monthly-report': `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Monthly Security Report</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #3b82f6; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f9f9f9; }
            .stats { display: flex; justify-content: space-around; margin: 20px 0; }
            .stat { text-align: center; }
            .stat-number { font-size: 24px; font-weight: bold; color: #3b82f6; }
            .button { display: inline-block; padding: 12px 24px; background: #3b82f6; color: white; text-decoration: none; border-radius: 4px; }
            .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Monthly Security Report</h1>
              <p>{{month}}</p>
            </div>
            <div class="content">
              <h2>Hi {{firstName}},</h2>
              <p>Here's your security summary for {{month}}:</p>
              <div class="stats">
                <div class="stat">
                  <div class="stat-number">{{totalAlerts}}</div>
                  <div>Total Alerts</div>
                </div>
                <div class="stat">
                  <div class="stat-number">{{threatsBlocked}}</div>
                  <div>Threats Blocked</div>
                </div>
                <div class="stat">
                  <div class="stat-number">{{complianceScore}}%</div>
                  <div>Compliance Score</div>
                </div>
                <div class="stat">
                  <div class="stat-number">{{apiUsage}}</div>
                  <div>API Requests</div>
                </div>
              </div>
              <p style="text-align: center;">
                <a href="{{dashboardUrl}}" class="button">View Full Report</a>
              </p>
            </div>
            <div class="footer">
              <p>The {{companyName}} Team</p>
              <p>Questions? Contact us at {{supportEmail}}</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    return templates[templateName] || '';
  }
}

module.exports = EmailService; 