const connection = require("../db-config");
const Joi = require("joi");
const argon2 = require("argon2");
const { calculateToken } = require("../helpers/user");

const db = connection.promise();

const validate = (data, forCreation = true) => {
  const presence = forCreation ? "required" : "optional";
  return Joi.object({
    email: Joi.string().email().max(255).presence(presence),
    password: Joi.string().min(8).max(50).presence(presence),
    firstname: Joi.string().max(255).presence(presence),
    lastname: Joi.string().max(255).presence(presence),
    city: Joi.string().allow(null, "").max(255),
    language: Joi.string().allow(null, "").max(255),
  }).validate(data, { abortEarly: false }).error;
};

const findMany = ({ filters: { language } }) => {
  let sql = "SELECT id, email, firstname, lastname, city, language FROM users";
  const sqlValues = [];
  if (language) {
    sql += " WHERE language = ?";
    sqlValues.push(language);
  }

  return db.query(sql, sqlValues).then(([results]) => results);
};

const findOne = (id) => {
  return db
    .query(
      "SELECT id, email, firstname, lastname, city, language FROM users WHERE id = ?",
      [id]
    )
    .then(([results]) => results[0]);
};

const findByEmail = (email) => {
  return db
    .query("SELECT * FROM users WHERE email = ?", [email])
    .then(([results]) => results[0]);
};

const findByToken = (token) => {
  return db.query("SELECT * FROM users WHERE token = ?", [token]);
};

const findByEmailWithDifferentId = (email, id) => {
  return db
    .query("SELECT * FROM users WHERE email = ? AND id <> ?", [email, id])
    .then(([results]) => results[0]);
};

const create = ({ firstname, lastname, city, language, email, password }) => {
  return hashPassword(password).then((hashedPassword) => {
    const token = calculateToken(email);
    return db
      .query("INSERT INTO users SET ?", {
        firstname,
        lastname,
        city,
        language,
        email,
        hashedPassword,
        token,
      })
      .then(([result]) => {
        const id = result.insertId;
        return { firstname, lastname, city, language, email, id, token };
      });
  });
};

const update = (id, newAttributes) => {
  console.log(newAttributes);
  const token = calculateToken(newAttributes.email);
  newAttributes.token = token;
  return db.query("UPDATE users SET ? WHERE id = ?", [newAttributes, id]);
};

const destroy = (id) => {
  return db
    .query("DELETE FROM users WHERE id = ?", [id])
    .then(([result]) => result.affectedRows !== 0);
};

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = (plainPassword) => {
  return argon2.hash(plainPassword, hashingOptions);
};

const verifyPassword = (plainPassword, hashedPassword) => {
  return argon2.verify(hashedPassword, plainPassword, hashingOptions);
};

module.exports = {
  findMany,
  findByToken,
  findOne,
  validate,
  create,
  update,
  destroy,
  findByEmail,
  findByEmailWithDifferentId,
  hashPassword,
  verifyPassword,
};
