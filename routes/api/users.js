const express = require("express");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const router = express.Router();
const { check, validationResult } = require("express-validator");
const User = require("../../models/User");

// @route         Post api/users
// @description   route used to register an user
// @acess         Public

router.post(
  "/",
  [
    check("name", "Name cannot be empty").not().isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check("password", "The minumun lenght is 6 characters").isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, password } = req.body;
      let user = await User.findOne({ email });
      if (user) {
        res.status(400).json({ errors: [{ msg: "The user already exists" }] });
      }
      const avatar = await gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm",
      });
      const salt = await bcrypt.genSalt(10);
      user = new User({
        name,
        email,
        password: await bcrypt.hash(password, salt),
        avatar,
      });

      await user.save();

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtToken"),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) {
            throw err;
          }
          res.send({ token });
        }
      );
    } catch (error) {
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
