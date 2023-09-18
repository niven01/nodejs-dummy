const axios = require("axios");
const FormData = require("form-data");
require("dotenv").config();
const {EMAIL_USER, EMAIL_DOMAIN, MAILGUN_AUTH} = process.env;

async function sendReferralEmail(invitee, referrer, company, types, referral_id) {
  return new Promise(async (resolve, reject) => {
    try {
      var data = new FormData();
      data.append("from", `Enexo <${EMAIL_USER}>`);
      data.append("to", invitee.email);
      data.append("subject", "Enexo - You've been invited to complete & share a Supply Chain Assessment");
      data.append("html", `<!DOCTYPE HTML
        PUBLIC "-//W3C//DTD XHTML 1.0 Transitional //EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
      <html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml"
        xmlns:o="urn:schemas-microsoft-com:office:office">
      
      <head>
        <!--[if gte mso 9]>
      <xml>
        <o:OfficeDocumentSettings>
          <o:AllowPNG/>
          <o:PixelsPerInch>96</o:PixelsPerInch>
        </o:OfficeDocumentSettings>
      </xml>
      <![endif]-->
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="x-apple-disable-message-reformatting">
        <!--[if !mso]><!-->
        <meta http-equiv="X-UA-Compatible" content="IE=edge"><!--<![endif]-->
        <title></title>
      
        <style type="text/css">
          @media only screen and (min-width: 580px) {
            .u-row {
              width: 560px !important;
            }
      
            .u-row .u-col {
              vertical-align: top;
            }
      
            .u-row .u-col-50 {
              width: 280px !important;
            }
      
            .u-row .u-col-100 {
              width: 560px !important;
            }
      
          }
      
          @media (max-width: 560px) {
            .u-row-container {
              max-width: 100% !important;
              padding-left: 0px !important;
              padding-right: 0px !important;
            }
      
            .u-row .u-col {
              min-width: 320px !important;
              max-width: 100% !important;
              display: block !important;
            }
      
            .u-row {
              width: 100% !important;
            }
      
            .u-col {
              width: 100% !important;
            }
      
            .u-col>div {
              margin: 0 auto;
            }
          }
      
          body {
            margin: 0;
            padding: 0;
          }
      
          table,
          tr,
          td {
            vertical-align: top;
            border-collapse: collapse;
          }
      
          p {
            margin: 0;
          }
      
          .ie-container table,
          .mso-container table {
            table-layout: fixed;
          }
      
          * {
            line-height: inherit;
          }
      
          a[x-apple-data-detectors='true'] {
            color: inherit !important;
            text-decoration: none !important;
          }
      
          table,
          td {
            color: #272662;
          }
      
          #u_body a {
            color: #0000ee;
            text-decoration: underline;
          }
        </style>
      
      
      
      </head>
      
      <body class="clean-body u_body"
        style="margin: 0;padding: 0;-webkit-text-size-adjust: 100%;background-color: #e7e7e7;color: #272662">
        <!--[if IE]><div class="ie-container"><![endif]-->
        <!--[if mso]><div class="mso-container"><![endif]-->
        <table id="u_body"
          style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;min-width: 320px;Margin: 0 auto;background-color: #e7e7e7;width:100%"
          cellpadding="0" cellspacing="0">
          <tbody>
            <tr style="vertical-align: top">
              <td style="word-break: break-word;border-collapse: collapse !important;vertical-align: top">
                <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" style="background-color: #e7e7e7;"><![endif]-->
      
      
                <div class="u-row-container" style="padding: 0px;background-color: transparent">
                  <div class="u-row"
                    style="Margin: 0 auto;min-width: 320px;max-width: 560px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
                    <div
                      style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                      <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:560px;"><tr style="background-color: transparent;"><![endif]-->
      
                      <!--[if (mso)|(IE)]><td align="center" width="560" style="background-color: #ffffff;width: 560px;padding: 8px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;" valign="top"><![endif]-->
                      <div class="u-col u-col-100"
                        style="max-width: 320px;min-width: 560px;display: table-cell;vertical-align: top;">
                        <div style="background-color: #ffffff;height: 100%;width: 100% !important;">
                          <!--[if (!mso)&(!IE)]><!-->
                          <div
                            style="box-sizing: border-box; height: 100%; padding: 8px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;">
                            <!--<![endif]-->
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px 10px 0px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
      
                                      <tr>
                                        <td style="padding-right: 0px;padding-left: 0px;" align="center">
      
                                          <img align="center" border="0"
                                            src="https://prd-cdn.enexo.io/enexo/images/enexoheader.png" alt="" title=""
                                            style="outline: none;text-decoration: none;-ms-interpolation-mode: bicubic;clear: both;display: inline-block !important;border: none;height: auto;float: none;width: 100%;max-width: 560px;"
                                            width="500" />
                                        </td>
                                      </tr>
                                    </table>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <table height="0px" align="center" border="0" cellpadding="0" cellspacing="0" width="100%"
                                      style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;border-top: 1px solid #c2e0d9;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                      <tbody>
                                        <tr style="vertical-align: top">
                                          <td
                                            style="word-break: break-word;border-collapse: collapse !important;vertical-align: top;font-size: 0px;line-height: 0px;mso-line-height-rule: exactly;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                            <span>&#160;</span>
                                          </td>
                                        </tr>
                                      </tbody>
                                    </table>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <!--[if (!mso)&(!IE)]><!-->
                          </div><!--<![endif]-->
                        </div>
                      </div>
                      <!--[if (mso)|(IE)]></td><![endif]-->
                      <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
                    </div>
                  </div>
                </div>
      
      
      
                <div class="u-row-container" style="padding: 0px;background-color: transparent">
                  <div class="u-row"
                    style="Margin: 0 auto;min-width: 320px;max-width: 560px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
                    <div
                      style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                      <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:560px;"><tr style="background-color: transparent;"><![endif]-->
      
                      <!--[if (mso)|(IE)]><td align="center" width="560" style="background-color: #ffffff;width: 560px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;" valign="top"><![endif]-->
                      <div class="u-col u-col-100"
                        style="max-width: 320px;min-width: 560px;display: table-cell;vertical-align: top;">
                        <div
                          style="background-color: #ffffff;height: 100%;width: 100% !important;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                          <!--[if (!mso)&(!IE)]><!-->
                          <div
                            style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                            <!--<![endif]-->
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td style="padding-right: 0px; padding-left: 0px;" align="center">
                                    <table style="font-family:arial,helvetica,sans-serif; font-size: 13px;"
                                      role="presentation" width="90%" cellpadding="0" cellspacing="0" border="0">
                                      <tr>
                                        <td align="center">
                                          <img border="0"
                                            src="https://prd-cdn.enexo.io/company-data-files/logos/${
        referrer.company_id
      }.png"
                                            alt="" title=""
                                            style="outline: none; text-decoration: none; -ms-interpolation-mode: bicubic; clear: both; display: inline-block !important; border: none; height: auto; float: none; width: 100%; max-width: 50px;"
                                            width="100" />
                                        </td>
                                        <td align="center" style="vertical-align: middle;">
                                          <p style=" line-height: 140%;">You've received an invite on behalf of
                                            <b>${
        referrer.company_name
      }</b>
                                          </p>
      
                                        </td>
                                      </tr>
      
                                    </table>
      
                                  </td>
                                </tr>
      
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px 15px 1px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <table height="0px" align="center" border="0" cellpadding="0" cellspacing="0" width="97%"
                                      style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;border-top: 1px solid #c2e0d9;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                      <tbody>
                                        <tr style="vertical-align: top">
                                          <td
                                            style="word-break: break-word;border-collapse: collapse !important;vertical-align: top;font-size: 0px;line-height: 0px;mso-line-height-rule: exactly;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                            <span>&#160;</span>
                                          </td>
                                        </tr>
                                      </tbody>
                                    </table>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px 15px 0px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <div style="font-size: 14px; line-height: 140%; text-align: left; word-wrap: break-word;">
                                      <p style="line-height: 140%;">Hi ${
        invitee.first_name
      },</p>
      
      
                                      <p style="line-height: 140%;"> </p>
                                      <p style="line-height: 140%;">${
        referrer.first_name
      }
                                      ${
        referrer.last_name
      } at ${
        referrer.company_name
      } has confirmed you
                                        as an authorised representative of ${
        company.name
      } ${
        company.id
      } and invited you to Enexo to complete and share a Supply Chain Assessment because your organisation holds a significant position within our value
                                        circle as a valued ${
        types[0]
      }. Enexo has been designed to support our
                                        sustainability initiatives by providing a collaborative space where we can
                                        collectively work towards creating a greener future.</p>
                                      <p style="line-height: 140%;"> </p>
                                      <p style="line-height: 140%;">To accept this invitation, simply follow the steps below:
                                      <p style="line-height: 140%;">
                                        <b>Please note that this step is solely for accepting the invitation, and there is no
                                          obligation to complete the assessment straight away.</b>
                                      </p>
                                      <p style="line-height: 140%;"> </p>
                                      <p style="line-height: 140%;">Sign up or login using the buttons below:</p>
                                      <p style="line-height: 100%;"> </p>
                                    </div>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                            <!--[if (!mso)&(!IE)]><!-->
                          </div><!--<![endif]-->
                        </div>
                      </div>
                      <!--[if (mso)|(IE)]></td><![endif]-->
                      <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
                    </div>
                  </div>
                </div>
      
      
      
                <div class="u-row-container" style="padding: 0px;background-color: transparent">
                  <div class="u-row"
                    style="Margin: 0 auto;min-width: 320px;max-width: 560px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
                    <div
                      style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                      <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:560px;"><tr style="background-color: transparent;"><![endif]-->
      
                      <!--[if (mso)|(IE)]><td align="center" width="280" style="background-color: #ffffff;width: 280px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;" valign="top"><![endif]-->
                      <div class="u-col u-col-50"
                        style="max-width: 320px;min-width: 280px;display: table-cell;vertical-align: top;">
                        <div
                          style="background-color: #ffffff;height: 100%;width: 100% !important;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                          <!--[if (!mso)&(!IE)]><!-->
                          <div
                            style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                            <!--<![endif]-->
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <!--[if mso]><style>.v-button {background: transparent !important;}</style><![endif]-->
                                    <div align="center">
                                      <!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="https://register.enexo.io?referral=${referral_id}" style="height:30px; v-text-anchor:middle; width:242px;" arcsize="11%"  stroke="f" fillcolor="#3AAEE0"><w:anchorlock/><center style="color:#FFFFFF;font-family:arial,helvetica,sans-serif;"><![endif]-->
                                      <a href="https://register.enexo.io?referral=${referral_id}" target="_blank"
                                        class="v-button"
                                        style="box-sizing: border-box;display: inline-block;font-family:arial,helvetica,sans-serif;text-decoration: none;-webkit-text-size-adjust: none;text-align: center;color: #FFFFFF; background-color: #3AAEE0; border-radius: 4px;-webkit-border-radius: 4px; -moz-border-radius: 4px; width:auto; max-width:100%; overflow-wrap: break-word; word-break: break-word; word-wrap:break-word; mso-border-alt: none;font-size: 14px;">
                                        <span style="display:block;padding:10px 20px;line-height:120%;"><span
                                            style="line-height: 16.8px;">Register for a new Enexo account<br /></span></span>
                                      </a>
                                      <!--[if mso]></center></v:roundrect><![endif]-->
                                    </div>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <!--[if (!mso)&(!IE)]><!-->
                          </div><!--<![endif]-->
                        </div>
                      </div>
                      <!--[if (mso)|(IE)]></td><![endif]-->
                      <!--[if (mso)|(IE)]><td align="center" width="280" style="background-color: #ffffff;width: 280px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;" valign="top"><![endif]-->
                      <div class="u-col u-col-50"
                        style="max-width: 320px;min-width: 280px;display: table-cell;vertical-align: top;">
                        <div
                          style="background-color: #ffffff;height: 100%;width: 100% !important;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                          <!--[if (!mso)&(!IE)]><!-->
                          <div
                            style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                            <!--<![endif]-->
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <!--[if mso]><style>.v-button {background: transparent !important;}</style><![endif]-->
                                    <div align="center">
                                      <!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="https://app.enexo.io/login?referral=${referral_id}" style="height:30px; v-text-anchor:middle; width:235px;" arcsize="11%"  stroke="f" fillcolor="#4ce0b1"><w:anchorlock/><center style="color:#FFFFFF;font-family:arial,helvetica,sans-serif;"><![endif]-->
                                      <a href="https://app.enexo.io/login?referral=${referral_id}"
                                        target="_blank" class="v-button"
                                        style="box-sizing: border-box;display: inline-block;font-family:arial,helvetica,sans-serif;text-decoration: none;-webkit-text-size-adjust: none;text-align: center;color: #FFFFFF; background-color: #4ce0b1; border-radius: 4px;-webkit-border-radius: 4px; -moz-border-radius: 4px; width:auto; max-width:100%; overflow-wrap: break-word; word-break: break-word; word-wrap:break-word; mso-border-alt: none;font-size: 14px;">
                                        <span style="display:block;padding:10px 20px;line-height:120%;"><span
                                            style="line-height: 16.8px;">Use an existing Enexo account<br /></span></span>
                                      </a>
                                      <!--[if mso]></center></v:roundrect><![endif]-->
                                    </div>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <!--[if (!mso)&(!IE)]><!-->
                          </div><!--<![endif]-->
                        </div>
                      </div>
                      <!--[if (mso)|(IE)]></td><![endif]-->
                      <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
                    </div>
                  </div>
                </div>
      
      
      
                <div class="u-row-container" style="padding: 0px;background-color: transparent">
                  <div class="u-row"
                    style="Margin: 0 auto;min-width: 320px;max-width: 560px;overflow-wrap: break-word;word-wrap: break-word;word-break: break-word;background-color: transparent;">
                    <div
                      style="border-collapse: collapse;display: table;width: 100%;height: 100%;background-color: transparent;">
                      <!--[if (mso)|(IE)]><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding: 0px;background-color: transparent;" align="center"><table cellpadding="0" cellspacing="0" border="0" style="width:560px;"><tr style="background-color: transparent;"><![endif]-->
      
                      <!--[if (mso)|(IE)]><td align="center" width="560" style="background-color: #ffffff;width: 560px;padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;" valign="top"><![endif]-->
                      <div class="u-col u-col-100"
                        style="max-width: 320px;min-width: 560px;display: table-cell;vertical-align: top;">
                        <div
                          style="background-color: #ffffff;height: 100%;width: 100% !important;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                          <!--[if (!mso)&(!IE)]><!-->
                          <div
                            style="box-sizing: border-box; height: 100%; padding: 0px;border-top: 0px solid transparent;border-left: 0px solid transparent;border-right: 0px solid transparent;border-bottom: 0px solid transparent;border-radius: 0px;-webkit-border-radius: 0px; -moz-border-radius: 0px;">
                            <!--<![endif]-->
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:0px 15px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <div style="font-size: 14px; line-height: 140%; text-align: left; word-wrap: break-word;">
                                      <ol>
                                        <li style="line-height: 19.6px;">Enter details and set a password</li>
                                        <li style="line-height: 19.6px;">Register your account / login to your account</li>
                                        <li style="line-height: 19.6px;">Select the mailbox icon in the Supply Chain
                                          module and accept</li>
                                        <li style="line-height: 19.6px;">Complete and publish your Supply Chain Assessment</li>
                                      </ol>
                                      <p style="line-height: 140%;">Once registered, you will have full access to the platform
                                        and its array of sustainability-focused features.</p>
                                      <p style="line-height: 140%;"> </p>
                                      <p style="line-height: 140%;">
                                        <b>Note: Please do not forward on this invite!</b>
                                      </p>
                                      <p style="line-height: 140%;">
                                        <b>Invites are unique and linked to your email address, other users will not be able to accept the invite on your behalf. 
                                          If you are not the appropriate recipient, please contact the sender and request that they issue a new invite to the appropriate person.</b></p>
                                      <p style="line-height: 140%;"> </p>
                                      <p style="line-height: 140%;">Together, we can make a significant difference in
                                        promoting sustainability and building a brighter future. I look forward to having you
                                        join us on Enexo as we embark on this exciting sustainability journey!
                                        <br /><br />Thank you,
                                      </p>
                                      <p style="line-height: 140%;">The Enexo Team</p>
                                    </div>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:10px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <table height="0px" align="center" border="0" cellpadding="0" cellspacing="0" width="100%"
                                      style="border-collapse: collapse;table-layout: fixed;border-spacing: 0;mso-table-lspace: 0pt;mso-table-rspace: 0pt;vertical-align: top;border-top: 1px solid #c2e0d9;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                      <tbody>
                                        <tr style="vertical-align: top">
                                          <td
                                            style="word-break: break-word;border-collapse: collapse !important;vertical-align: top;font-size: 0px;line-height: 0px;mso-line-height-rule: exactly;-ms-text-size-adjust: 100%;-webkit-text-size-adjust: 100%">
                                            <span>&#160;</span>
                                          </td>
                                        </tr>
                                      </tbody>
                                    </table>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <table style="font-family:arial,helvetica,sans-serif;" role="presentation" cellpadding="0"
                              cellspacing="0" width="100%" border="0">
                              <tbody>
                                <tr>
                                  <td
                                    style="overflow-wrap:break-word;word-break:break-word;padding:0px 15px 12px;font-family:arial,helvetica,sans-serif;"
                                    align="left">
      
                                    <div style="font-size: 12px; line-height: 140%; text-align: left; word-wrap: break-word;">
                                      <p style="line-height: 140%;"><span style="color: #95a5a6; line-height: 16.8px;">The
                                          content of this email is confidential and intended for the recipient specified in
                                          message only. It is strictly forbidden to share any part of this message with any
                                          third party, without a written consent of the sender. If you received this message
                                          by mistake, please reply to this message and follow with its deletion, so that we
                                          can ensure such a mistake does not occur in the future.</span></p>
                                    </div>
      
                                  </td>
                                </tr>
                              </tbody>
                            </table>
      
                            <!--[if (!mso)&(!IE)]><!-->
                          </div><!--<![endif]-->
                        </div>
                      </div>
                      <!--[if (mso)|(IE)]></td><![endif]-->
                      <!--[if (mso)|(IE)]></tr></table></td></tr></table><![endif]-->
                    </div>
                  </div>
                </div>
      
      
                <!--[if (mso)|(IE)]></td></tr></table><![endif]-->
              </td>
            </tr>
          </tbody>
        </table>
        <!--[if mso]></div><![endif]-->
        <!--[if IE]></div><![endif]-->
      </body>
      
      </html>
          `);

      const mailGunRes = await axios({
        method: "post",
        url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
        headers: {
          Authorization: MAILGUN_AUTH,
          ... data.getHeaders()
        },
        data: data
      });
      console.log(mailGunRes.data);
      resolve(mailGunRes.data);
    } catch (error) {
      reject(error);
    }
  });
}

module.exports = {
  sendReferralEmail
};
