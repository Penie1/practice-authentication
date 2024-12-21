require("dotenv").config();
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.PG_HOST,
  password: process.env.PG_PASSWORD,
  user: process.env.PG_USER,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});
app.get("/", (req, res) => {
  res.render("index");
});
app.get("/sign-up", (req, res) => {
  res.render("sign-up-form");
});
app.post("/sign-up", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(`INSERT INTO users (username,password) VALUES($1,$2)`, [
      username,
      hashedPassword,
    ]);
    res.redirect("/");
  } catch (error) {
    return next(error);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);
app.get("/log-out", (req, res, next) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        `SELECT * FROM users WHERE username = $1`,
        [username]
      );
      const user = rows[0];
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (error) {
      done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
    const user = rows[0];
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.listen(3000, () => console.log("Server listening on port 3000!"));
