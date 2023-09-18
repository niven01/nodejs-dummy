const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const FormData = require("form-data");
let router = express.Router();

// REGISTER ROUTE

function possessiveStr(string) {
  if (string == "") {
    return string;
  }
  var lastChar = string.slice(-1);
  var endOfWord = lastChar.toLowerCase() == "s" ? `'` : `'s`;
  return `${string}${endOfWord}`;
}

function toTitleCase(str) {
  return str.replace(/\w\S*/g, function (txt) {
    return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
  });
}

const {
  EMAIL_USER,
  MAILGUN_AUTH,
  HASURA_ENEXO_SECRET,
  HASURA_ENEXO_ENDPOINT,
  EMAIL_DOMAIN
} = process.env;

async function updateUserFields(id, _set) {
  try {
    const {data} = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify(
        {
          query: `mutation MyMutation($id: uuid = "", $_set: user_set_input = {}) {
          update_user_by_pk(pk_columns: {id: $id}, _set: $_set) {
            active_company_id
            verified
            active_organisation_id
          }
        }                
        `,
          variables: {
            id,
            _set: _set
          }
        }
      )
    });

    if (data) {
      console.log(data);
    }
  } catch (error) {
    console.log(error.message);
  }
}

async function updateInviteToSent(id, _set) {
  try {
    const {data} = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify(
        {
          query: `mutation MyMutation($id: uuid = "", $_set: tenant_invite_set_input = {}) {
          update_tenant_invite_by_pk(pk_columns: {id: $id}, _set: $_set) {
            email_response
            email_delivered
            email_sent_at
          }
        }                
        `,
          variables: {
            id,
            _set: {
              ... _set,
              email_delivered: true
            }
          }
        }
      )
    });

    if (data) {
      console.log(data);
    }
  } catch (error) {
    console.log(error.message);
  }
}

async function getInviterDetail(user) {
  try {
    console.log(user);
    const {data} = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify(
        {
          query: `query getInviterDetail($id: uuid!) {
  user_by_pk(id: $id) {
    first_name
    last_name
    email
    tenant {
      company {
        name
      }
    }
    active_company_id
    active_organisation_id
  }
}        
        `,
          variables: {
            id: user.invited_by_user_id
          }
        }
      )
    });

    if (data) {
      const usr = data.data.user_by_pk;
      console.log(usr);
      return {
        ... usr,
        company_name: usr.tenant.company.name
      };
    }
  } catch (error) {
    console.log(error.message);
  }
}

async function sendInviteEmail(user) {
  try {
    const inviter = await getInviterDetail(user);
    let inviteRaw = `${
      user.invite_token
    }:${
      user.email
    }`;
    let buff = new Buffer(inviteRaw);
    let invite64data = buff.toString("base64");
    var data = new FormData();
    data.append("from", `Enexo <${EMAIL_USER}>`);
    data.append("to", user.email);
    data.append("subject", `You're invited to join ${
      possessiveStr(toTitleCase(inviter.company_name))
    } Enexo Organisation`);
    data.append("text", `${
      toTitleCase(inviter.first_name)
    } wants you to join them on Enexo, go to https://register.enexo.io/?invite=${invite64data} to create your account.`);

    const mailGunRes = await axios({
      method: "post",
      url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
      headers: {
        Authorization: MAILGUN_AUTH,
        ... data.getHeaders()
      },
      data: data
    });
    if (mailGunRes && mailGunRes.data) {
      const email_sent_at = new Date().toISOString();
      const email_response = mailGunRes.data;
      updateInviteToSent(user.id, {email_response, email_sent_at});
      updateUserFields(user.id, {
        active_company_id: inviter.active_company_id,
        active_organisation_id: inviter.active_organisation_id,
        verified: true
      });
      return {
        data: {
          status: 200,
          response: email_response
        }
      };
    }
  } catch (error) {
    return {
      data: {
        status: 500,
        error: error.message
      }
    };
    console.log("sendInviteEmail: ", error.message);
  }
}

router.post("/invite", async (req, res, next) => {
  try {
    const inviteRes = await sendInviteEmail(req.body.event.data.new);
    res.json(inviteRes);
  } catch (e) {
    console.log(e);
    res.status(500).json(e.toString());
  }
});

module.exports = router;
