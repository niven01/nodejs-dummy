const { GraphQLClient } = require('graphql-request');

const {
  HASURA_ENEXO_ENDPOINT,
  HASURA_ENEXO_SECRET
} = require('../config');

const graphql_client = new GraphQLClient(HASURA_ENEXO_ENDPOINT, {
  headers: {
    'Content-Type': 'application/json',
    'x-hasura-admin-secret': HASURA_ENEXO_SECRET,
  },
});


async function hasuraCheckAdmin(user) {
  try {
    const {user_by_pk} = await graphql_client.request(`query isUserTenantAdmin($id: uuid!) {
      user_by_pk(id: $id) {
        tenant_id
        is_tenant_admin
      }
    }
    `, {
      id: user.id,
    });
    if (user_by_pk) {
      console.log(user_by_pk)
      const isAdmin = user_by_pk.is_tenant_admin
      if (isAdmin && user_by_pk.tenant_id) {
        if (user_by_pk.tenant_id === user.tenant_id) {
          return true
        }
      }
      return false
    }
  } catch (error) {
    console.log(error.message)
  }
}

module.exports = hasuraCheckAdmin