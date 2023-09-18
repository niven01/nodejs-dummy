const axios = require("axios");
const { HASURA_ENEXO_ENDPOINT, HASURA_ENEXO_SECRET } = require("../config");
const { queryHasura, insertHasura } = require("../services/hasura");
const { query } = require("express");
function getUserData(apiAuth) {
  return new Promise(async (resolve, reject) => {
    const { data } = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET,
      },
      data: JSON.stringify({
        query: `query user($apiAuth: uuid!) {
          user (where: {id: {_eq: $apiAuth}}) {
            id
            first_name
            last_name
            email
            tenant_id
          }
        }           
        `,
        variables: {
          apiAuth,
        },
      }),
    });
    try {
      if (data && data.data.user) {
        resolve(data.data.user[0]);
      } else {
        reject("No user in app database.");
        return;
      }
    } catch (e) {
      reject("Server error");
    }
  });
}

function updateUserLogin(apiAuth) {
  return new Promise(async (resolve, reject) => {
    const data = await insertHasura(
      `mutation ($user_id: uuid!, $object: user_set_input!) {
            update_user_by_pk(pk_columns: {id: $user_id}, _set: $object) {
              id
            }
          }           
          `,
      {
        user_id: apiAuth,
        object: {
          last_login: new Date(),
        },
      }
    );
    try {
      console.log(data);
      if (data && data.update_user_by_pk?.id) {
        resolve(data.update_user_by_pk.id);
      } else {
        reject("No user in app database.");
        return;
      }
    } catch (e) {
      console.log(e);
      reject("Server error");
    }
  });
}

module.exports = {
  getUserData,
  updateUserLogin,
};
