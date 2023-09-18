const axios = require("axios");

const { HASURA_ENEXO_ENDPOINT, HASURA_ENEXO_SECRET } = require("../config");

async function insertHasura(query, variables) {
  try {
    const { data } = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET,
      },
      method: "POST",
      data: JSON.stringify({
        query,
        variables,
      }),
    });
    return Object.values(data.data)[0];
  } catch (error) {
    console.log(error.message);
  }
}

async function queryHasura(query, variables) {
  try {
    const { data } = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET,
      },
      method: "POST",
      data: JSON.stringify({
        query,
        variables,
      }),
    });
    return Object.values(data.data)[0];
  } catch (error) {
    console.log(error.message);
  }
}

module.exports = { insertHasura, queryHasura };
