const axios = require("axios");
const FormData = require("form-data");
const fsPromises = require("fs").promises;
require("dotenv").config();

const { EMAIL_USER, EMAIL_DOMAIN, MAILGUN_AUTH } = process.env;

async function sendWelcomeEmail(user) {
  try {
    var data = new FormData();
    data.append("from", `Enexo <${EMAIL_USER}>`);
    data.append("to", user.email);
    data.append("subject", `Welcome to Enexo! Your account has been verified`);
    data.append(
      "html",
      `<html>
      <body
        style="font-family: 'Calibri', sans-serif; font-size: 11pt; margin: 0cm"
      >
        <div>
          <div align="center">
            <table
              border="0"
              cellspacing="0"
              cellpadding="0"
              style="border-collapse: collapse"
            >
              <tbody>
                <tr>
                  <td>
                    <p>
                      <img
                        width="615"
                        height="175"
                        style="width: 8.507in; height: 1.8229in"
                        src="cid:image_banner.png"
                        alt="Enexo Banner Image"
                      />
                    </p>
                  </td>
                </tr>
                <tr>
                  <td>
                    <br />
                    <h3 style="color: #404040;">
                      Welcome to Enexo.
                    </h3>
                    <p class="MsoNormal">
                      <span style="color: #404040"
                        >We're thrilled to have you on board, and we're even more
                        excited to help you and your business reach your carbon
                        reduction goals using Enexo. To help you get started, here
                        are a few key pieces of information...</span
                      >
                    </p>
                  </td>
                </tr>
                <tr>
                  <td
                    width="623"
                    valign="top"
                    style="width: 467.5pt; padding: 0cm 5.4pt 0=cm 5.4pt"
                  >
                    <p>
                      <strong
                        ><span>
                          <o:p>&nbsp;</o:p>
                        </span></strong
                      >
                    </p>
                    <p>
                      <b>
                        <span style="font-size: 12pt; color: #0c0932"
                          >How to access...</span
                        >
                        <br /> </b
                      ><span style="color: #404040">Enexo login page: </span
                      ><a href="https://app.enexo.io/login"
                        >https://app.enexo.io/login</a
                      ><span style="color: #3b3838"> </span>
                    </p>
                    <p>
                      <span style="color: #404040"
                        >Log in with the email address and password you used to
                        register.
                        <br />
                        Your password can be reset from the settings menu.<br />
                        <br />
                        If you want to invite team members to your Enexo space, you
                        can add them from the organisation settings menu.</span
                      >
                    </p>
                  </td>
                </tr>
                <tr>
                  <td
                    width="623"
                    valign="top"
                    style="width: 467.5pt; padding: 0cm 5.4pt 0=cm 5.4pt"
                  >
                    <p>
                      <strong
                        ><span>
                          <o:p>&nbsp;</o:p>
                        </span></strong
                      >
                    </p>
                    <p>
                      <b
                        ><span style="font-size: 12pt; color: #0c0932"
                          >Support...</span
                        > </b
                      ><b
                        ><span style="font-size: 12pt"><br /> </span></b
                      ><span style="color: #404040"
                        >If you need help, don't worry, we'll walk you through every
                        step.
                        <br />
                        We have a customer portal where you can submit support
                        tickets, suggest new features and more.</span
                      ><br />
                      <br />
                      <b
                        ><span style="color: #404040"
                          >You can find this here:</span
                        ></b
                      ><b>
                        <span style="font-size: 12pt; color: #404040"> </span> </b
                      ><a
                        href="https://enexo.atlassian.net/servicedesk/customer/portals"
                        >https://enexo.atlassian.net/servicedesk/customer/portals</a
                      ><b><span style="font-size: 12pt"> </span></b>
                    </p>
                    <p>&nbsp;</p>
                    <p>
                      <span style="color: #404040"
                        >We also have a knowledge base containing how-to guides for
                        all areas of Enexo.</span
                      ><span style="color: #3b3838"> <br /> <br /> </span
                      ><b><span style="color: #404040">Knowledge Base:</span></b
                      ><b>
                        <span style="font-size: 12pt; color: #404040"> </span> </b
                      ><a href="https://enexo.atlassian.net/wiki/spaces/EH/pages"
                        >https://enexo.atlassian.net/wiki/spaces/EH/pages</a
                      ><br />
                      <br />
                      <br />
                      <br />
                      <b
                        ><span style="font-size: 12pt; color: #0c0932"
                          >One last thing...</span
                        ></b
                      ><b><br /> </b
                      ><span style="color: #404040"
                        >Enexo is still in active development, and we are making new
                        enhancements each day. We thank you again for agreeing to
                        become a valued early adopter of the platform.<br />
                        <br />
                        This is an opportunity to gain direct, mutually beneficial
                        value by contributing to this innovative project during this
                        beta phase - your feedback will help shape the development
                        of the platform and allow you to experience an innovative
                        new methodology for corporate emissions recording.</span
                      ><br />
                      <br />
                      <br />
                      <br /><span style="color: #404040"
                        >Thank you,<br />
                        The Enexo Team</span
                      >
                    </p>
                    <p>
                      <span style="font-size: 8.5pt; color: dimgray"
                        >The content of this email is confidential and intended for
                        the recipient specified in message only. It is strictly
                        forbidden to share any part of this message with any third
                        party, without a written consent of the sender. If you
                        received this message by mistake, please reply to this
                        message and follow with its deletion, so that we can ensure
                        such a mistake does not occur in the future.</span
                      >
                    </p>
                    <p class="MsoNormal">
                      <o:p>&nbsp;</o:p>
                    </p>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p>
            <span style="font-size: 12pt">
              <o:p>&nbsp;</o:p>
            </span>
          </p>
        </div>
      </body>
    </html>
    `
    );
    data.append(
      "inline",
      await fsPromises.readFile("./assets/image_banner.png"),
      "image_banner.png"
    );

    const mailGunRes = await axios({
      method: "post",
      url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
      headers: {
        Authorization: MAILGUN_AUTH,
        ...data.getHeaders(),
      },
      data: data,
    });

    console.log(mailGunRes.data);
  } catch (error) {
    console.log(error);
    console.log("sendWelcomeEmail: ", error.message);
  }
}

module.exports = {
  sendWelcomeEmail,
};
