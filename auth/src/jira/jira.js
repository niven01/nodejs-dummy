const express = require('express');
const Boom = require('boom');
const Joi = require('joi');
const { GraphQLClient } = require('graphql-request');
const { sendWelcomeEmail } = require('../enexo/emails')
require('dotenv').config();
const axios = require('axios');

const {
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME,
  HASURA_ENDPOINT,
  HASURA_SECRET,
  JIRA_USERNAME,
  JIRA_API_PASSWORD
} = require('../config');

const auth = {
  username: JIRA_USERNAME,
  password: JIRA_API_PASSWORD,
};

const schema_name =
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME === 'public'
    ? ''
    : USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + '_';

const graphql_client = new GraphQLClient(HASURA_ENDPOINT, {
  headers: {
    'Content-Type': 'application/json',
    'x-hasura-admin-secret': HASURA_SECRET,
  },
});

let router = express.Router();

router.post('/request', async (req, res, next) => {
  // Get user data from request

  const schema = Joi.object().keys({
    email: Joi.string().required(),
    company_id: Joi.string().required(),
    company_name: Joi.string().required(),
    watchlist: Joi.array().items(
      Joi.object().keys({
        name: Joi.string().required(),
        id: Joi.string().required(),
      })
    ),
  });

  const { error, value: bodyValues } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  // CHECK AUTHENTICATION
  const refresh_token = req.cookies['refresh_token'];

  let query = `
  query get_refresh_token(
    $refresh_token: uuid!
  ) {
    ${schema_name}refresh_tokens (
      where: {
        refresh_token: { _eq: $refresh_token }
      }
    ) {
      user {
        id
        auth_id
      }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      refresh_token,
    });
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized('Invalid refresh token request'));
  }

  if (hasura_data[`${schema_name}refresh_tokens`].length === 0) {
    return next(Boom.unauthorized('invalid refresh token'));
  }

  // Get on JIRA and populate fields
  const { email, company_id, company_name, watchlist } = bodyValues;

  const headers = {
    'Content-Type': 'application/json',
  };

  const descriptionContent = watchlist.map((el, index) => ({
    type: 'paragraph',
    content: [
      {
        type: 'text',
        text: `Company ${index + 1}: `,
        marks: [
          {
            type: 'strong',
          },
        ],
      },
      {
        type: 'text',
        text: `${el.name} (${el.id})`,
      },
    ],
  }));

  const body = {
    fields: {
      project: { id: 10000 },
      summary: `Watchlist Request - ${email} - ${company_id}`,
      description: {
        type: 'doc',
        version: 1,
        content: descriptionContent,
      },
      issuetype: { name: 'Support' },
      customfield_10041: email,
      customfield_10040: company_name,
      customfield_10042: company_id,
    },
  };

  try {
    await axios({
      method: 'POST',
      url: 'https://enexo.atlassian.net/rest/api/3/issue/',
      auth,
      headers,
      data: body,
    });

    res.status(200);
    res.send('OK');
  } catch (e) {
    console.log(e);
    res.status(400);
    res.send(e);
  }
});

// ---------------------------------------------------
// ---------------------------------------------------
// ****************** REGISTER ***********************
// ---------------------------------------------------
// ---------------------------------------------------

router.post('/register', async (req, res, next) => {
  // Get user data from request

  const schema = Joi.object().keys({
    first_name: Joi.string().required(),
    last_name: Joi.string().required(),
    email: Joi.string().required(),
    company_id: Joi.string().required(),
    company_name: Joi.string().required(),
  });

  const { error, value: bodyValues } = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  // CHECK AUTHENTICATION
  const refresh_token = req.cookies['refresh_token'];

  let query = `
  query get_refresh_token(
    $refresh_token: uuid!
  ) {
    ${schema_name}refresh_tokens (
      where: {
        refresh_token: { _eq: $refresh_token }
      }
    ) {
      user {
        id
        auth_id
      }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      refresh_token,
    });
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized('Invalid refresh token request'));
  }

  if (hasura_data[`${schema_name}refresh_tokens`].length === 0) {
    return next(Boom.unauthorized('invalid refresh token'));
  }

  // Get on JIRA and populate fields
  const { email, company_id, company_name, first_name, last_name } = bodyValues;

  sendWelcomeEmail({ email })

  const headers = {
    'Content-Type': 'application/json',
  };

  const body = {
    fields: {
      project: { id: 10000 },
      summary: `User Registration - ${email} - ${company_id}`,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              {
                type: 'text',
                text: `User has finished onboarding process: `,
                marks: [
                  {
                    type: 'strong',
                  },
                ],
              },
              {
                type: 'text',
                text: `${first_name} (${last_name})`,
              },
            ],
          }
        ],
      },
      issuetype: { name: 'Support' },
      customfield_10041: email,
      customfield_10040: company_name,
      customfield_10042: company_id,
    },
  };

  try {
    await axios({
      method: 'POST',
      url: 'https://enexo.atlassian.net/rest/api/3/issue/',
      auth,
      headers,
      data: body,
    });

    res.status(200);
    res.send('OK');
  } catch (e) {
    console.log(e);
    res.status(400);
    res.send(e);
  }
});

module.exports = router;
