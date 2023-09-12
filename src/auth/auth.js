const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const Boom = require("boom");
const uuidv4 = require("uuid/v4");
const minioClient = require("./minio-client");
const multer = require("multer");
const upload = multer();
const {GraphQLClient} = require("graphql-request");
require("dotenv").config();
const {getUserData, updateUserLogin} = require("../shared/app-data");
const axios = require("axios");
const FormData = require("form-data");
const {sendWelcomeEmail, sendReferralEmail, sendBulkReferralEmail} = require("../enexo/emails");

const {
  USER_FIELDS,
  USER_REGISTRATION_AUTO_ACTIVE,
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME,
  REFRESH_TOKEN_EXPIRES,
  JWT_TOKEN_EXPIRES,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  EMAIL_USER,
  EMAIL_DOMAIN,
  MAILGUN_AUTH,
  HASURA_ENDPOINT,
  HASURA_SECRET,
  HASURA_ENEXO_ENDPOINT,
  HASURA_ENEXO_SECRET,
  AUTH_DOMAIN
} = require("../config");

const graphql_client = new GraphQLClient(HASURA_ENDPOINT, {
  headers: {
    "Content-Type": "application/json",
    "x-hasura-admin-secret": HASURA_SECRET
  }
});

const auth_tools = require("../shared/auth-tools");

let router = express.Router();

const schema_name = USER_MANAGEMENT_DATABASE_SCHEMA_NAME === "public" ? "" : USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + "_";

// REGISTER ROUTE
router.post("/register", async (req, res, next) => {
  let password_hash;
  let confirmedInvite = false;
  let inviteParams = {};

  const schema = Joi.object().keys({
    first_name: Joi.string().required(),
    last_name: Joi.string().required(),
    username: Joi.string().required(),
    password: Joi.string().required(),
    validation_method: Joi.string().required(),
    tel: Joi.string().required()
  });

  const {error, value} = schema.validate(req.body, {allowUnknown: true});

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  let {
    first_name,
    last_name,
    username,
    password,
    validation_method,
    tel,
    invite_token
  } = value;

  username = username.toLowerCase();

  if (invite_token) {
    const inviteCheck = await axios({
      url: HASURA_ENEXO_ENDPOINT,
      method: "POST",
      headers: {
        "x-hasura-admin-secret": HASURA_ENEXO_SECRET
      },
      data: JSON.stringify(
        {
          query: `query MyQuery($invite_token: uuid!, $email: String!) {
          tenant_invite(where: {invite_token: {_eq: $invite_token}, email: {_eq: $email}}) {
            id
            tenant_id
            invited_by_user_id
            is_admin
          }
        }
        `,
          variables: {
            invite_token,
            email: username
          }
        }
      )
    });

    if (inviteCheck && inviteCheck.data && inviteCheck.data.data) {
      const checkResult = inviteCheck.data.data.tenant_invite[0];
      inviteParams = checkResult;
      confirmedInvite = true;
      sendWelcomeEmail({email: username});
    } else {
      return next(Boom.badRequest("Sorry your invitation link isn't valid anymore."));
    }
  }

  const validation_code = Math.floor(100000 + Math.random() * 900000).toString();
  // generate password_hash
  try {
    password_hash = await bcrypt.hash(password, 10);
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation("Unable to generate 'password hash'"));
  }

  // insert user
  query = `
    mutation (
      $user: ${schema_name}users_insert_input!
    ) {
      insert_${schema_name}users(
        objects: [$user]
      ) {
        affected_rows
      }
    }
  `;
  let userObject = {
    first_name: first_name,
    last_name: last_name,
    username: username,
    password: password_hash,
    secret_token: uuidv4(),
    active: USER_REGISTRATION_AUTO_ACTIVE,
    validation_code: validation_code,
    validation_method: validation_method,
    tel: tel,
    invite_token
  };
  if (confirmedInvite) {
    userObject.auth_id = inviteParams.id;
  }

  try {
    await graphql_client.request(query, {user: userObject});

    if (validation_method === "SMS") { // SEND SMS MESSAGE //

      const accountSid = TWILIO_ACCOUNT_SID;
      const authToken = TWILIO_AUTH_TOKEN;
      const client = require("twilio")(accountSid, authToken);

      client.messages.create({body: `Your verification code for Enexo is ${validation_code}`, from: "+447723455465", to: tel}).then((message) => console.log(message.sid));

      // END SEND SMS MESSAGE //
      // SEND EMAIL MESSAGE //
    } else if (validation_method === "email") {
      var data = new FormData();
      data.append("from", `Enexo <${EMAIL_USER}>`);
      data.append("to", username);
      data.append("subject", "Your Enexo verification code");
      data.append("text", `Your verification code for Enexo is ${validation_code}, enter this on the Enexo website to validate your account.`);
      var config = {
        method: "post",
        url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
        headers: {
          Authorization: MAILGUN_AUTH,
          ... data.getHeaders()
        },
        data: data
      };
      axios(config).then(function (response) {
        console.log("Email has been sent succesfully");
        console.log(response);
        console.log(JSON.stringify(response.data));
      }).catch(function (error) {
        console.log(error);
      });
    }
    // END SEND EMAIL MESSAGE //
  } catch (e) {
    console.log(e);
    let isDuplicateError = e.response.errors.filter(({extensions: {
        code
      }}) => code === "constraint-violation").length > 0;
    if (isDuplicateError) {
      return next(Boom.badRequest("A user with that email address already exists."));
    }
    return next(Boom.badImplementation("Unable to create user."));
  }

  res.send("OK");
});

// LOGOUT ROUTE
router.post("/logout", async (req, res, next) => {
  res.cookie("refresh_token", "", {
    httpOnly: true,
    expires: new Date(0),
    secure: true,
    sameSite: "none",
    // domain: AUTH_DOMAIN,
  });

  const refresh_token = req.cookies["refresh_token"];

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
      }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {refresh_token});
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized("Invalid refresh token request"));
  }

  const user_id = hasura_data[`${schema_name}refresh_tokens`][0].user.id;

  // Clear existing refresh tokens
  removeTokensQuery = `
      mutation (
        $user_id: Int!
      ) {
        delete_${schema_name}refresh_tokens (
          where: {
            user_id: { _eq: $user_id }
          }
        ) {
          affected_rows
        }
      }
    `;
  try {
    const removed = await graphql_client.request(removeTokensQuery, {user_id});
  } catch (e) {
    console.error(e);
    // return next(Boom.badImplementation('Could not remove old refresh tokens'));
  }
  // End of Clear existing refresh tokens

  res.send("OK");
});

// LOGIN ROUTE
router.post("/login", async (req, res, next) => { // validate username and password
  const schema = Joi.object().keys({username: Joi.string().required(), password: Joi.string().required(), application: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {username, password, application} = value;
  // const { username, password } = value;

  let query = `
  query (
    $username: String!
  ) {
    ${schema_name}users (
      where: {
        username: { _eq: $username}
      }
    ) {
      id
      first_name
      last_name
      password
      active
      default_role
      auth_id
      is_verified
      roles: users_x_roles {
        role
      }
      ${
    USER_FIELDS.join("\n")
  }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {username});
  } catch (e) {
    console.error(e);
    // console.error('Error connection to GraphQL');
    return next(Boom.unauthorized("Unable to find 'user'"));
  }

  if (hasura_data[`${schema_name}users`].length === 0) { // console.error("No user with this 'username'");
    return next(Boom.unauthorized("Invalid username or password"));
  }

  // check if we got any user back
  const user = hasura_data[`${schema_name}users`][0];

  if (user.is_verified === false) {
    return next(Boom.unauthorized("Please verify your account or contact support."));
  }

  // see if password hashes matches
  const match = await bcrypt.compare(password, user.password);

  if (! match) {
    console.error("Password does not match");
    return next(Boom.unauthorized("Invalid 'username' or 'password'"));
  }
  console.warn("user: " + JSON.stringify(user, null, 2));

  // Get tenant_id from correspoding app db
  try {
    appUserData = await getUserData(user.auth_id, application);
    user.tenant_id = appUserData ?. tenant_id || "";
  } catch (e) {
    console.log(e);
  }

  // User is already registered with enexo so update last_login column
  if (user.tenant_id && application === "enexo") {
    try {
      await updateUserLogin(user.auth_id, application);
    } catch (e) {
      console.log(e);
    }
  }

  // Clear existing refresh tokens
  removeTokensQuery = `
    mutation (
      $user_id: Int!
    ) {
      delete_${schema_name}refresh_tokens (
        where: {
          user_id: { _eq: $user_id }
        }
      ) {
        affected_rows
      }
    }
  `;
  try {
    await graphql_client.request(removeTokensQuery, {user_id: user.id});
  } catch (e) {
    console.error(e);
    // return next(Boom.badImplementation('Could not remove old refresh tokens'));
  }
  // End of Clear existing refresh tokens

  const jwt_token = await auth_tools.generateJwtToken(user, application);
  const jwt_token_expiry = new Date(new Date().getTime() + JWT_TOKEN_EXPIRES * 60 * 1000);

  console.log("jwt_token");
  console.log(jwt_token);

  // generate refresh token and put in database
  query = `
  mutation (
    $refresh_token_data: ${schema_name}refresh_tokens_insert_input!
  ) {
    insert_${schema_name}refresh_tokens (
      objects: [$refresh_token_data]
    ) {
      affected_rows
    }
  }
  `;

  const refresh_token = uuidv4();
  try {
    await graphql_client.request(query, {
      refresh_token_data: {
        user_id: user.id,
        refresh_token: refresh_token,
        expires_at: new Date(new Date().getTime() + REFRESH_TOKEN_EXPIRES * 60 * 1000), // convert from minutes to milli seconds
      }
    });
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation("Could not update 'refresh token' for user"));
  }

  res.cookie("refresh_token", refresh_token, {
    maxAge: REFRESH_TOKEN_EXPIRES * 60 * 1000, // convert from minute to milliseconds
    sameSite: "none",
    httpOnly: true,
    secure: true,
    // domain: AUTH_DOMAIN,
  });

  // return jwt token and refresh token to client
  res.json({
    jwt_token,
    refresh_token,
    jwt_token_expiry,
    first_name: user.first_name,
    last_name: user.last_name,
    tenant_id: user ?. tenant_id || null,
    auth_id: ! user ?. tenant_id ? user.auth_id : null
  });
});

// REFRESH TOKEN ROUTE
router.post("/refresh-token", async (req, res, next) => {
  const schema = Joi.object().keys({application: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {application} = value;

  const refresh_token = req.cookies["refresh_token"];
  console.log("refresh_token");
  console.log(refresh_token);

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
          username
          password
          active
          default_role
          first_name
          last_name
          auth_id
          roles: users_x_roles {
            role
          }
          ${
    USER_FIELDS.join("\n")
  }
        }
      }
    }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {refresh_token});
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized("Invalid refresh token request"));
  }

  console.log("------------------------");
  console.log("hasura_data");
  console.log(hasura_data);
  console.log(hasura_data[`${schema_name}refresh_tokens`]);

  if (hasura_data[`${schema_name}refresh_tokens`].length === 0) {
    return next(Boom.unauthorized("invalid refresh token"));
  }

  const user = hasura_data[`${schema_name}refresh_tokens`][0].user;
  const user_id = user.id;

  // delete current refresh token and generate a new, and insert the
  // new refresh_token in the database
  // two mutations as transaction
  query = `
  mutation (
    $old_refresh_token: uuid!,
    $new_refresh_token_data: refresh_tokens_insert_input!
    $user_id: Int!
  ) {
    delete_${schema_name}refresh_tokens (
      where: {
        _and: [{
          refresh_token: { _eq: $old_refresh_token }
        }, {
          user_id: { _eq: $user_id }
        }]
      }
    ) {
      affected_rows
    }
    insert_${schema_name}refresh_tokens (
      objects: [$new_refresh_token_data]
    ) {
      affected_rows
    }
  }
  `;

  const new_refresh_token = uuidv4();
  try {
    await graphql_client.request(query, {
      old_refresh_token: refresh_token,
      new_refresh_token_data: {
        user_id: user_id,
        refresh_token: new_refresh_token,
        expires_at: new Date(new Date().getTime() + REFRESH_TOKEN_EXPIRES * 60 * 1000), // convert from minutes to milli seconds
      },
      user_id
    });
  } catch (e) {
    console.error(e);
    // console.error('unable to create new refresh token and delete old');
    return next(Boom.unauthorized("Invalid 'refresh_token' or 'user_id'"));
  }

  // Get tenant_id from correspoding app db
  try {
    appUserData = await getUserData(user.auth_id, application);
    user.tenant_id = appUserData ?. tenant_id || "";
  } catch (e) {
    console.log(e);
  }

  // generate new jwt token
  const jwt_token = await auth_tools.generateJwtToken(user, application);
  const jwt_token_expiry = new Date(new Date().getTime() + JWT_TOKEN_EXPIRES * 60 * 1000);

  res.cookie("refresh_token", new_refresh_token, {
    maxAge: REFRESH_TOKEN_EXPIRES * 60 * 1000, // convert from minute to milliseconds
    httpOnly: true,
    secure: true,
    sameSite: "none",
    // domain: AUTH_DOMAIN,
  });

  res.json({
    jwt_token,
    jwt_token_expiry,
    refresh_token: new_refresh_token,
    refresh_token_expiry: REFRESH_TOKEN_EXPIRES * 60 * 1000,
    user_id,
    username: user.username,
    first_name: user.first_name,
    last_name: user.last_name,
    tenant_id: user ?. tenant_id || null,
    auth_id: ! user ?. tenant_id ? user.auth_id : null
  });
});

router.post("/upload", upload.single("avatar"), async (req, res, next) => {
  const refresh_token = req.cookies["refresh_token"];

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
    hasura_data = await graphql_client.request(query, {refresh_token});
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized("Invalid refresh token request"));
  }

  if (hasura_data[`${schema_name}refresh_tokens`].length === 0) {
    return next(Boom.unauthorized("invalid refresh token"));
  }

  const user = hasura_data[`${schema_name}refresh_tokens`][0].user;

  let filename = user.auth_id;
  filename = "users/" + filename;
  filename += "." + req.file.mimetype.split("/")[1];

  minioClient.putObject("enexo", filename, req.file.buffer, function (error, etag) {
    if (error) {
      return console.log(error);
    }
    res.sendStatus(200);
  });
});

// Validation ROUTE
router.post("/validate", async (req, res, next) => { // validate username and password
  const schema = Joi.object().keys({username: Joi.string().required(), validationCode: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {username, validationCode} = value;

  let query = `
  query (
    $username: String!
  ) {
    ${schema_name}users (
      where: {
        username: { _eq: $username}
      }
    ) {
      id
      validation_code
      validation_attempts
      active
      default_role
      auth_id
      roles: users_x_roles {
        role
      }
      ${
    USER_FIELDS.join("\n")
  }
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {username: username.toLowerCase()});
  } catch (e) {
    console.error(e);
    // console.error('Error connection to GraphQL');
    return next(Boom.unauthorized("Unable to find 'user'"));
  }

  if (hasura_data[`${schema_name}users`].length === 0) { // console.error("No user with this 'username'");
    return next(Boom.unauthorized("Invalid 'username'"));
  }

  // check if we got any user back
  const user = hasura_data[`${schema_name}users`][0];

  // see if code matches
  if (user.validation_attempts < 1) {
    return next(Boom.unauthorized("Maximum attempts reached. Please request a new validation code."));
  }

  const match = validationCode === user.validation_code;

  if (! match) {
    console.error("Validation code does not match");
    query = {
      query: `mutation MyMutation($username: String!, $validation_attempts: Int!) {
       update_users(where: {username: {_eq: $username}}, _set: {validation_attempts: $validation_attempts}) {
         affected_rows
       }
      }`,
      variables: {
        username: username.toLowerCase(),
        validation_attempts: user.validation_attempts - 1
      }
    };
    try {
      response = await graphql_client.request(query.query, query.variables);
      console.log(response);
      if (user.validation_attempts < 1) {
        return next(Boom.unauthorized("Maximum attempts reached. Please request a new validation code."));
      } else {
        return next(Boom.unauthorized("Invalid account or validation code"));
      }
    } catch (e) {
      console.error(e);
      return next(Boom.unauthorized("Invalid account or validation code"));
    }
  } else {
    query = {
      query: `mutation MyMutation($username: String!) {
       update_users(where: {username: {_eq: $username}}, _set: {default_role: "user", is_verified: true}) {
         affected_rows
       }
      }`,
      variables: {
        username: username.toLowerCase()
      }
    };

    try {
      response = await graphql_client.request(query.query, query.variables);
      console.log(response);
      res.send("OK");
      try {
        const axios = require("axios");
        const updateInviteStatus = await axios({
          url: HASURA_ENEXO_ENDPOINT,
          method: "POST",
          headers: {
            "x-hasura-admin-secret": HASURA_ENEXO_SECRET
          },
          data: JSON.stringify(
            {
              query: `mutation MyMutation($id: uuid!, $_set: user_set_input = {}) {
            update_user_by_pk(pk_columns: {id: $id}, _set: $_set) {
              status
              id
            }
          }
          `,
              variables: {
                id: user.auth_id,
                _set: {
                  status: "active"
                }
              }
            }
          )
        });
        console.log(updateInviteStatus);
      } catch (error) {
        console.log(error.message);
      }
    } catch (e) {
      console.error(e);
      return next(Boom.unauthorized("Invalid validation"));
    }
  }
  console.warn("user: " + JSON.stringify(user, null, 2));
});

// Resend code ROUTE
router.post("/resend", async (req, res, next) => { // validate username
  const schema = Joi.object().keys({username: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {username} = value;
  const newValidationCode = Math.floor(100000 + Math.random() * 900000).toString();

  query = {
    query: `mutation MyMutation($username: String = "", $validation_code: String = "") {
      update_users(where: {username: {_eq: $username}}, _set: {validation_code: $validation_code, validation_attempts: 3}) {
        affected_rows
      }
    }`,
    variables: {
      username: username.toLowerCase(),
      validation_code: newValidationCode
    }
  };
  try {
    response = await graphql_client.request(query.query, query.variables);
    console.log(response);

    // Send email with new code
    var data = new FormData();
    data.append("from", `Enexo <${EMAIL_USER}>`);
    data.append("to", username);
    data.append("subject", "Your Enexo verification code");
    data.append("text", `Your new verification code for Enexo is ${newValidationCode}, go to https://register.enexo.io/validate/${username} to validate your account.`);

    var config = {
      method: "post",
      url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
      headers: {
        Authorization: MAILGUN_AUTH,
        ... data.getHeaders()
      },
      data: data
    };

    axios(config).then(function (response) {
      console.log(JSON.stringify(response.data));
    }).catch(function (error) {
      console.log(error);
    });
  } catch (e) {
    console.error(e);
    return next(Boom.badRequest("Error sending new validation code"));
  }
  res.send("OK");
});

router.post("/password-update", async (req, res, next) => {
  const refresh_token = req.cookies["refresh_token"];

  // validate username and password
  const schema = Joi.object().keys({password: Joi.string().required(), passwordNew: Joi.string().required(), passwordNewConfirm: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {password, passwordNew, passwordNewConfirm} = value;

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
          username
          password
          active
          default_role
          first_name
          last_name
          auth_id
          roles: users_x_roles {
            role
          }
          ${
    USER_FIELDS.join("\n")
  }
        }
      }
    }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {refresh_token});
  } catch (e) {
    console.error(e);
    return next(Boom.unauthorized("Invalid refresh token request"));
  }

  if (hasura_data[`${schema_name}refresh_tokens`].length === 0) { // console.error("No user with this 'username'");
    return next(Boom.unauthorized("Couldn't find user."));
  }

  const user = hasura_data[`${schema_name}refresh_tokens`][0].user;

  // see if password hashes matches
  const match = await bcrypt.compare(password, user.password);

  if (! match) {
    console.error("Invalid current 'password'");
    return next(Boom.unauthorized("Invalid current 'password'"));
  }
  console.warn("user: " + JSON.stringify(user, null, 2));

  if (passwordNew !== passwordNewConfirm) {
    console.error("New password and its confirmation differs.");
    return next(Boom.unauthorized("New password and its confirmation differs."));
  }

  try {
    password_hash = await bcrypt.hash(passwordNew, 10);
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation("Unable to generate 'password hash'"));
  }

  // update password
  query = `
    mutation updateUser($usersPk: users_pk_columns_input!, $userObj: users_set_input) {
      update_users_by_pk(pk_columns: $usersPk, _set: $userObj) {
        id
      }
    }
  `;

  try {
    await graphql_client.request(query, {
      usersPk: {
        id: user.id
      },
      userObj: {
        password: password_hash
      }
    });
  } catch (e) {
    console.log(e);
    return next(Boom.badImplementation("Unable to update password. Try again later."));
  }

  res.send("OK");
});

router.post("/forgot-password", async (req, res, next) => { // validate username
  const schema = Joi.object().keys({username: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {username} = value;

  let query = `
  query (
    $username: String!
  ) {
    users (
      where: {
        username: { _eq: $username}
      }
    ) {
      id
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {username});
  } catch (e) {
    console.error(e);
    console.error("GraphQL error'");
    return next(Boom.badRequest("Sorry, we've encountered a problem. Please try again later."));
  }

  if (hasura_data[`users`].length === 0) { // Don't show if user exist.
    console.error("No user with this 'username'");
    return res.send("OK");
    // return next(Boom.unauthorized('Check your email to continue password reset process.'));
  }

  const user = hasura_data[`users`][0];

  // Create token and hash it

  const passwordResetToken = uuidv4();

  const resetTokenObject = {
    reset_token: passwordResetToken,
    user_id: user.id,
    // 2h expiration time
    expires_at: new Date(new Date().getTime() + 120 * 60 * 1000)
  };

  // Store password refresh token in the api-auth db on users table
  query = {
    query: `mutation insertResetToken($object: reset_tokens_insert_input!) {
      insert_reset_tokens_one(object: $object
        on_conflict: {
          constraint: reset_tokens_pkey,
          update_columns: [reset_token, expires_at]
        }
      ) {
        id
      }
    }`,
    variables: {
      object: resetTokenObject
    }
  };

  let queryRes;

  try {
    queryRes = await graphql_client.request(query.query, query.variables);
  } catch (e) {
    console.error(e);
    return next(Boom.badRequest("Sorry, we've encountered a problem. Please try again later."));
  }

  // Send email with the link to reset password
  if (queryRes ?. insert_reset_tokens_one ?. id) {
    var data = new FormData();
    data.append("from", `Enexo <${EMAIL_USER}>`);
    data.append("to", username);
    data.append("subject", "Enexo - Reset your password");
    data.append("text", `Hi, \n\nTo reset your password, please click on the link below:\n\nhttps://app.enexo.io/reset-password?token=${passwordResetToken}`);

    const config = {
      method: "post",
      url: `https://api.eu.mailgun.net/v3/${EMAIL_DOMAIN}/messages`,
      headers: {
        Authorization: MAILGUN_AUTH,
        ... data.getHeaders()
      },
      data: data
    };

    try {
      axios(config).then(function (response) {
        console.log(JSON.stringify(response.data));
      }).catch(function (error) {
        console.log(error);
      });
    } catch (e) {
      return next(Boom.badRequest("Error sending an email. Please try again later or contact support."));
    }
  }

  res.send("OK");
});

router.post("/reset-password", async (req, res, next) => { // validate username and password
  const schema = Joi.object().keys({username: Joi.string().required(), passwordNew: Joi.string().required(), passwordNewConfirm: Joi.string().required(), passwordResetToken: Joi.string().required()});

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {username, passwordResetToken, passwordNew, passwordNewConfirm} = value;

  // check if user exists and get it

  let query = `
  query (
    $username: String!
  ) {
    users (
      where: {
        username: { _eq: $username}
      }
    ) {
      id
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {username});
  } catch (e) {
    console.error(e);
    console.error("GraphQL error'");
    return next(Boom.badRequest("Sorry, we've encountered a problem. Please try again later."));
  }

  if (hasura_data[`users`].length === 0) { // Don't show if user exist.
    console.error("No user with this 'username'");
    return next(Boom.badRequest("Sorry we couldn't process your request. Please check your details."));
  }

  const user = hasura_data[`users`][0];

  // Get db token compare it and check expiration time
  query = {
    query: `query resetToken($userId: Int!) {
      reset_tokens(where: {user_id: {_eq: $userId}}) {
        user_id
        reset_token
        expires_at
      }
    }`,
    variables: {
      userId: user.id
    }
  };

  let response;

  try {
    response = await graphql_client.request(query.query, query.variables);

    console.log(response);
  } catch (e) {
    console.error(e);
  }

  if (response.reset_tokens.length === 0 ||
  // does user match
  response.reset_tokens[0].user_id !== user.id ||
  // is token the same
  response.reset_tokens[0].reset_token !== passwordResetToken) {
    return next(Boom.badRequest("Sorry we couldn't process your request. Please check your details."));
  }

  // is token expired
  if (new Date(response.reset_tokens[0].expires_at).getTime() < new Date().getTime()) {
    return next(Boom.unauthorized("Reset link has expired."));
  }

  // Check if passwords are the same
  if (passwordNew !== passwordNewConfirm) {
    console.error("New password and its confirmation differs.");
    return next(Boom.unauthorized("New password and its confirmation differs."));
  }

  try {
    password_hash = await bcrypt.hash(passwordNew, 10);
  } catch (e) {
    console.error(e);
    return next(Boom.badImplementation("Unable to generate 'password hash'"));
  }

  // update password
  query = `
    mutation updateUser($usersPk: users_pk_columns_input!, $userObj: users_set_input) {
      update_users_by_pk(pk_columns: $usersPk, _set: $userObj) {
        id
      }
    }
  `;

  try {
    await graphql_client.request(query, {
      usersPk: {
        id: user.id
      },
      userObj: {
        password: password_hash
      }
    });
  } catch (e) {
    console.log(e);
    return next(Boom.badImplementation("Unable to update password. Try again later."));
  }

  // Remove reset token
  removeToken = `
      mutation (
        $userId: Int!
      ) {
        delete_${schema_name}reset_tokens (
          where: {
            user_id: { _eq: $userId }
          }
        ) {
          affected_rows
        }
      }
    `;
  try {
    const removed = await graphql_client.request(removeToken, {userId: user.id});

    console.log("removed token", removed);
  } catch (e) {
    console.error(e);
    // return next(Boom.badImplementation('Could not remove old refresh tokens'));
  }

  res.send("OK");
});

async function insertReferral(referral_data) {
  return new Promise(async (resolve, reject) => {
    try {
      const {data} = await axios({
        url: HASURA_ENEXO_ENDPOINT,
        method: "POST",
        headers: {
          "x-hasura-admin-secret": HASURA_ENEXO_SECRET
        },
        data: JSON.stringify(
          {
            query: `mutation($referred_company_id: String, $referrer_tenant_id: uuid, $referrer_user_id: uuid, $referrer_user_name: String, $referrer_company_name: String, $referrer_company_id: String, $types: jsonb) {
            insert_esg_referral_one(object: {referred_company_id: $referred_company_id, referrer_tenant_id: $referrer_tenant_id, referrer_user_id: $referrer_user_id, referrer_user_name: $referrer_user_name, referrer_company_name: $referrer_company_name, referrer_company_id: $referrer_company_id, types: $types}) {
              id
            }
          }
          `,
            variables: {
              referred_company_id: referral_data.company_id,
              referrer_company_name: referral_data.referrer.company_name,
              referrer_company_id: referral_data.referrer.company_id,
              referrer_user_name: `${
                referral_data.referrer.first_name
              } ${
                referral_data.referrer.last_name
              }`,
              referrer_tenant_id: referral_data.referrer.tenant_id,
              referrer_user_id: referral_data.referrer.id,
              types: referral_data.types
            }
          }
        )
      });
      resolve(data);
    } catch (error) {
      reject(error);
    }
  });
}

router.post("/send-referral", async (req, res, next) => {
  const schema = Joi.object().keys({
    company_name: Joi.string().required(),
    company_id: Joi.string().required(),
    types: Joi.array().required(),
    invitee: Joi.object().keys(
      {first_name: Joi.string(), last_name: Joi.string(), email: Joi.string().email()}
    ).required(),
    referrer: Joi.object().keys(
      {
        first_name: Joi.string(),
        last_name: Joi.string(),
        company_name: Joi.string(),
        company_id: Joi.string(),
        tenant_id: Joi.string(),
        id: Joi.string()
      }
    ).required(),
    auth_checks: Joi.boolean()
  });

  const {error, value} = schema.validate(req.body);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }

  const {
    company_name,
    company_id,
    types,
    invitee,
    referrer,
    auth_checks
  } = value;

  const company = {
    name: company_name,
    id: company_id
  };

  let referral_id = "";

  let referral_data = {
    company_id: company_id,
    referrer: referrer,
    types: types
  };

  try {
    const inserted = await insertReferral(referral_data);
    if (inserted && inserted.data && inserted.data.insert_esg_referral_one) {
      referral_id = inserted.data.insert_esg_referral_one.id;
    }
  } catch (e) {
    console.error(e);
    return next(Boom.badRequest(e.details[0].message));
  }

  sendReferralEmail(invitee, referrer, company, types, referral_id).then(() => {
    res.send("OK");
  }).catch((error) => {
    console.error(error);
    return next(Boom.badRequest("Error sending an email. Please try again later or contact support."));
  });
});
async function insertBulkReferrals(bulkData) {
  const objects = bulkData.map((data) => ({
    referred_company_id: data.company_id,
    referrer_company_name: data.referrer.company_name,
    referrer_company_id: data.referrer.company_id,
    referrer_user_name: `${
      data.referrer.first_name
    } ${
      data.referrer.last_name
    }`,
    referrer_tenant_id: data.referrer.tenant_id,
    referrer_user_id: data.referrer.id,
    types: data.type
  }));
  return new Promise(async (resolve, reject) => {
    try {
      const {data} = await axios({
        url: HASURA_ENEXO_ENDPOINT,
        method: "POST",
        headers: {
          "x-hasura-admin-secret": HASURA_ENEXO_SECRET
        },
        data: JSON.stringify(
          {query: `mutation MyMutation($objects: [esg_referral_insert_input!] = {}) {
            insert_esg_referral(objects: $objects, on_conflict: {constraint: esg_referral_pkey, update_columns: []}) {
              affected_rows
              returning {
                id
              }
            }
          }
          
          `, variables: {
              objects
            }}
        )
      });
      resolve(data);
    } catch (error) {
      reject(error);
    }
  });
}
router.post("/send-referrals", async (req, res, next) => {
  const schema = Joi.array().items(Joi.object().keys({
    company_name: Joi.string().required(),
    company_id: Joi.string().required(),
    type: Joi.array().required(),
    invitee: Joi.object().keys(
      {first_name: Joi.string().required(), last_name: Joi.string().required(), email: Joi.string().email().required()}
    ).required(),
    referrer: Joi.object().keys(
      {
        first_name: Joi.string().required(),
        last_name: Joi.string().required(),
        company_name: Joi.string().required(),
        company_id: Joi.string().required(),
        tenant_id: Joi.string().required(),
        id: Joi.string().required()
      }
    ).required(),
    auth_checks: Joi.boolean().required()
  }));
  const {error, value} = schema.validate(req.body.bulkData);

  if (error) {
    return next(Boom.badRequest(error.details[0].message));
  }
  const bulkData = value;
  let returnedIds = [];

  try {
    const inserted = await insertBulkReferrals(bulkData);
    if (inserted && inserted.data) {
      returnedIds = inserted.data.insert_esg_referral.returning.map((referral) => referral.id);
    }
  } catch (e) {
    console.error(e);
    return next(Boom.badRequest(e.details[0].message));
  }
  bulkDataMap = bulkData.map((item, index) => ({
    ...item,
    referral_id: returnedIds[index]
  }));
  sendBulkReferralEmail(bulkDataMap).then(() => {
    res.send("OK");
  }).catch((error) => {
    console.error(error);
    return next(Boom.badRequest("Error sending an email. Please try again later or contact support."));
  });
});

module.exports = router;
