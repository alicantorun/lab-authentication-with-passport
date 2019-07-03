const ensureLogin = require("connect-ensure-login");

const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");

const User = require("../models/User");
const passportRouter = express.Router();

passportRouter.get("/signup", (req, res) => {
  res.render("passport/signup");
});

passportRouter.get("/login", (req, res) => {
  res.render(
    "passport/login",

    { errorMessage: req.flash("error") }
  );
});

passportRouter.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
  })
);

passportRouter.post("/signup", (req, res) => {
  const { username, password } = req.body;
  console.log(username);
  console.log(password);

  if (!password || !username) {
    res.render("passport/signup", { errorMessage: "Both fields are required" });

    return;
  } else if (password.length < 8) {
    res.render("passport/signup", {
      errorMessage: "Password needs to be 8 chars min"
    });

    return;
  }

  User.findOne({ username: username })
    .then(user => {
      if (user) {
        res.render("passport/signup", {
          errorMessage: "This username is already taken"
        });

        return;
      }

      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);

      return User.create({
        username,
        password: hash
      }).then(data => {
        res.redirect("/");
      });
    })
    .catch(err => {
      res.render("passport/signup", { errorMessage: err._message });
    });
});

passportRouter.get(
  "/private-page",
  ensureLogin.ensureLoggedIn(),
  (req, res) => {
    res.render("passport/private", { User: req.User });
  }
);

module.exports = passportRouter;
