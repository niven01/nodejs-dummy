const axios = require("axios");
require("dotenv").config();
const fs = require("fs");
const { EMAIL_USER, EMAIL_DOMAIN, MAILGUN_KEY } = process.env;
const formData = require("form-data");
const Mailgun = require("mailgun.js");

const mailgun = new Mailgun(formData);
const htmlString = fs.readFileSync("src/enexo/emails/referral.html", "utf8");
const client = mailgun.client({
  username: "api",
  key: MAILGUN_KEY,
  url: "https://api.eu.mailgun.net",
});
async function sendBulkReferralEmail(bulkData) {
  const recipients = bulkData.map((item) => item.invitee.email);

  const recipientVariables = bulkData.reduce((acc, item, index) => {
    acc[item.invitee.email] = {
      invitee_first_name: item.invitee.first_name,
      invitee_last_name: item.invitee.last_name,
      invitee_email: item.invitee.email,
      referral_id: item.referral_id,
      company_name: item.company_name,
      company_id: item.company_id,
      referrer_first_name: item.referrer.first_name,
      referrer_last_name: item.referrer.last_name,
      referrer_company_name: item.referrer.company_name,
      referrer_company_id: item.referrer.company_id,
      referrer_tenant_id: item.referrer.tenant_id,
      referrer_id: item.referrer.id,
      type: item.type.toString(),
    };
    return acc;
  }, {});

  let recipientsString = recipients.join(", ");

  try {
    const data = {
      from: `Enexo <${EMAIL_USER}>`,
      to: recipientsString,
      subject: "Enexo - You've been invited to complete & share a Supply Chain Assessment",
      html: htmlString,
      "recipient-variables": JSON.stringify(recipientVariables),
    };

    const res = await client.messages.create(EMAIL_DOMAIN, data);
    console.log(res);
    return res;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

module.exports = { sendBulkReferralEmail };
