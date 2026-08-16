import nodemailer from "nodemailer";
import pug from "pug";

import logger from "../config/logger.js";
import finalConfig from "../config/keys.js";

/**
 * Class representing an email utility for sending emails.
 */
class Email {
  constructor(user, code) {
    this.to = user.email;
    this.firstName = user.fullName.split(" ")[0];
    this.code = code;
    this.from = `Test Auth < ${finalConfig.email.from}>`;
  }

  /**
   * Creates a new transport for sending emails using nodemailer.
   * @returns {Object} A nodemailer transport object.
   */
  newTransport() {
    return nodemailer.createTransport({
      host: finalConfig.email.host,
      port: finalConfig.email.port,
      secure: false, // false means "use STARTTLS instead of immediate TLS"
      requireTLS: true, // Forces STARTTLS upgrade
      auth: {
        user: finalConfig.email.user,
        pass: finalConfig.email.pass,
      },
      connectionTimeout: 10000, // 10 seconds
      greetingTimeout: 10000, // 10 seconds
      socketTimeout: 10000, // 10 seconds
    });
  }

  /**
   * Sends an email using a specified template and subject.
   * @param {string} template - The Pug template to use for the email.
   * @param {string} subject - The subject of the email.
   * @returns {Promise<void>} - A promise that resolves when the email is sent.
   */
  async send(template, subject) {
    const html = pug.renderFile(
      `${import.meta.dirname}/../views/${template}.pug`,
      {
        firstName: this.firstName,
        code: this.code,
        subject,
      },
    );

    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
    };

    await this.newTransport().sendMail(mailOptions);
  }

  // Sends an email confirmation for user registration.
  async sendEmailConfirmation() {
    await this.send("register", "Confirm your email address");
  }
}

export default Email;
