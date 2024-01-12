const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("./utils/jwt-promisify");
const bcrypt = require("bcrypt");
const PORT = 5050;
const app = express();

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

const users = {};
const SECRET = "biggestsecret";

app.get("/", (req, res) => {
  // let id;
  // const userId = req.cookies["userId"];

  // if (userId) {
  //   id = userId;
  //   console.log({ session });
  // } else {
  //   id = uuid();
  //   session[id] = {
  //     secret: "my secret",
  //   };
  //   res.cookie("userId", id);
  //}

  const payload = { id: 123, username: "qni", age: 6 };
  const secret = "biggestsecret";
  const options = { expiresIn: "3d" };

  //            syncronous code
  const token = jwt.sign(payload, secret, options);

  res.send(token);
});

app.get("/verification/:token", (req, res) => {
  const { token } = req.params;
  //            Asyncronous code
  const result = jwt.verify(token, "biggestsecret");
  console.log({ result });
  res.send("ok");
});

app.get("/login", (req, res) => {
  console.log({ users });

  res.send(`
<h3>Login</h3>
  <form method="post">
<label for="username">Username</label>
<input type="text" name="username">

<label for="password">Password</label>
<input type="password" name="password">

<input type="submit" value="Submit">
</form>
`);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const preservedHsh = users[username]?.password;

  //                        removes the salt and compares pure hashes
  const isValid = await bcrypt.compare(password, preservedHsh);

  if (isValid) {
    // res.send("successfully authenticated");
    const payload = { username };

    try {
      const token = await jwt.sign(payload, SECRET, { expiresIn: "3d" });

      //set jwt as cookie
      res.cookie("token", token);
      res.redirect("/profile");
    } catch (error) {
      console.log({ error });
      res.redirect("/");
    }
  } else {
    res.status(401).send("unauthorized");
  }
});

app.get("/register", (req, res) => {
  res.send(`
<h3>Register</h3>
<form method="post">
<label for="username">Username</label>
<input type="text" name="username">

<label for="password">Password</label>
<input type="password" name="password">

<input type="submit" value="Submit">
</form>`);
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const salt = await bcrypt.genSalt(10); //by default -> 10
  const hash = await bcrypt.hash(password, salt);
  users[username] = { password: hash };

  res.redirect("/login");
});

app.get("/profile", async (req, res) => {
  const token = req.cookies["token"];
  console.log({ token });

  if (token) {
    try {
      const payload = await jwt.verify(token, SECRET);
      return res.send(`profile ${payload.username}`);
    } catch (error) {
      return res.status(401).send("unauthorised");
    }
  } else {
    return res.redirect("/login");
  }
});

app.listen(PORT, () => console.log(`Server is running on port: ${PORT}`));
