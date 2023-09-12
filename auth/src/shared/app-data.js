const axios = require('axios');
const {HASURA_ENEXO_ENDPOINT, HASURA_ENEXO_SECRET, HASURA_FIELDFUSION_ENDPOINT, HASURA_FIELDFUSION_SECRET} = require('../config');

const APPLICATION_MAPPING = [{
    application: 'enexo',
    url: HASURA_ENEXO_ENDPOINT,
    secret: HASURA_ENEXO_SECRET
  },];

function getUserData(apiAuth, application) {
  return new Promise(async (resolve, reject) => {
    const applicationData = APPLICATION_MAPPING.find((appData) => appData.application === application);
    if (! applicationData || applicationData.length < 1) {
      reject(`Application ${application} hasn't been found.`);
      return;
    }

    const {data} = await axios({
      url: applicationData.url,
      method: 'POST',
      headers: {
        'x-hasura-admin-secret': applicationData.secret
      },
      data: JSON.stringify(
        {query: `query user($apiAuth: uuid!) {
          user (where: {id: {_eq: $apiAuth}}) {
            id
            first_name
            last_name
            email
            tenant_id
          }
        }           
        `, variables: {
            apiAuth
          }}
      )
    });
    try {
      if (data && data.data.user) {
        resolve(data.data.user[0]);
      } else {
        reject('No user in app database.');
        return;
      }
    } catch (e) {
      reject('Server error');
    }
  });
}

function updateUserLogin(apiAuth, application) {
  return new Promise(async (resolve, reject) => {
    const applicationData = APPLICATION_MAPPING.find((appData) => appData.application === application);
    if (! applicationData || applicationData.length < 1) {
      reject(`Application ${application} hasn't been found.`);
      return;
    }

    const {data} = await axios({
      url: applicationData.url,
      method: 'POST',
      headers: {
        'x-hasura-admin-secret': applicationData.secret
      },
      data: JSON.stringify(
        {
          query: `mutation ($user_id: uuid!, $object: user_set_input!) {
            update_user_by_pk(pk_columns: {id: $user_id}, _set: $object) {
              id
            }
          }           
          `,
          variables: {
            user_id: apiAuth,
            object: {
              last_login: new Date()
            }
          }
        }
      )
    });
    try {
      if (data && data.data.update_user_by_pk ?. id) {
        resolve(data.data.update_user_by_pk.id);
      } else {
        reject('No user in app database.');
        return;
      }
    } catch (e) {
      console.log(e);
      reject('Server error');
    }
  });
}

module.exports = {
  getUserData,
  updateUserLogin
};
