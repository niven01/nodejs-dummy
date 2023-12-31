var axios = require('axios');
var FormData = require('form-data');
require('dotenv').config()

function possessiveStr(string) {
  if(string == '') {
    return string;
  }
  var lastChar = string.slice(-1);
  var endOfWord = lastChar.toLowerCase() == 's' ? `'` : `'s`;
  return `${string}${endOfWord}`;
}

function toTitleCase(str) {
  return str.replace(
    /\w\S*/g,
    function(txt) {
      return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
    }
  );
}

const { EMAIL_USER, MAILGUN_AUTH, HASURA_ENEXO_SECRET, HASURA_ENEXO_ENDPOINT, EMAIL_DOMAIN } = process.env

async function updateInviteToSent(id, _set) {
  try {
    const { data } = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify({
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
            ..._set,
            email_delivered: true
          }
        }
      })
    })

    if (data) {
      console.log(data.data)
    }
  } catch (error) {
    console.log(error.message)
  }
}

async function getInviterDetail(user) {
  try {
    const { data } = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify({
        query: `query getInviterDetail($id: uuid!) {
          user_by_pk(id: $id) {
            first_name
            last_name
            email
            tenant {
              organisation {
                company {
                  name
                }
              }
            }
          }
        }        
        `,
        variables: {
          id: user.invited_by_user_id
        }
      })
    })

    if (data) {
      const usr = data.data.user_by_pk
      return {
        ...usr,
        company_name: usr.tenant.organisation.company[0].name
      }
    }
  } catch (error) {
    console.log(error.message)
  }
}

async function sendInviteEmail(user) {
  try {
    const inviter = await getInviterDetail(user)
    var data = new FormData();
    data.append('from', `Enexo <${EMAIL_USER}>`);
    data.append('to', user.email);
    data.append('subject', `You're invited to join ${possessiveStr(toTitleCase(inviter.company_name))} Enexo Organisation`);
    data.append(
      'text',
      `${toTitleCase(inviter.first_name)} wants you to join them on Enexo, go to https://enexo-landing.redsmart.app/validate/${user.invite_token} to validate your account.`
    );

    console.log(data)

    const mailGunRes = await axios({
      method: 'post',
      url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
      headers: {
        Authorization: MAILGUN_AUTH,
        ...data.getHeaders(),
      },
      data: data,
    })
    if (mailGunRes && mailGunRes.data) {
      const email_sent_at = new Date().toISOString()
      const email_response = mailGunRes.data
      console.log((user.id, {
        email_response,
        email_sent_at
      }))
      updateInviteToSent(user.id, {
        email_response,
        email_sent_at
      })

    }
  } catch (error) {
    console.log("sendInviteEmail: ", error.message)
  }
}


module.exports = { sendInviteEmail }