const nodemailer = require('nodemailer');

const sendEmail = async options => {
    console.log(options)
    // 1) Create a transporter 
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD
        }
    })
    // 2( define the email options)

    const mailOptions = {
        from: 'bunthai chhorm <bunthai@gmail.com>',
        to: options.email,
        subject: options.subject,
        text: options.message,
        // html:
    }
    // console.log(mailOptions)

    // actually send the email
    await transporter.sendMail(mailOptions);
    console.log("Sending mail")
    
}
module.exports = sendEmail;