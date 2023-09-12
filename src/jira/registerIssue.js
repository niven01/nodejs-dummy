const axios = require('axios');
const {
  JIRA_USERNAME,
  JIRA_API_PASSWORD
} = require('../config');

const auth = {
  username: JIRA_USERNAME,
  password: JIRA_API_PASSWORD,
};

const registerIssue = ({ name, email }) => {

  const headers = {
    'Content-Type': 'application/json',
  };

  const body = {
    fields: {
      project: { id: 10000 },
      summary: `Registered user - ${email} (${name})`,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              {
                type: 'text',
                text: `E-mail: `,
                marks: [
                  {
                    type: 'strong',
                  },
                ],
              },
              {
                type: 'text',
                text: email,
              },
            ],
          },
        ]
      },
      issuetype: { name: 'Support' },
      customfield_10041: name,
    },
  };

  return new Promise(async (resolve, reject) => {
    try {
      await axios({
        method: 'POST',
        url: 'https://enexo.atlassian.net/rest/api/3/issue/',
        auth,
        headers,
        data: body,
      });

      resolve();
    } catch (e) {
      console.error(e);
      reject("Couldn't add the JIRA request");
      reject(e);
    }
  });
};

module.exports = { registerIssue };
