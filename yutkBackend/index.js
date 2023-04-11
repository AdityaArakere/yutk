require("dotenv").config();

const bcrypt = require("bcrypt");
const salt = bcrypt.genSaltSync(10);
const express = require("express");
const cors = require("cors");
const mysql = require("mysql");

const app = express();
const PORT = 3003;
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
  host: process.env.HOST,
});

app.post("/Reg", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const RegPassHash = await bcrypt.hash(password, salt);
  console.log(username);
  db.query(
    "INSERT INTO logindetails VALUES(?,?)",
    [username, RegPassHash],
    (err, result) => {
      if (err) console.log(err);
    }
  );
});

app.post("/Login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.query(
    "SELECT username, password FROM logindetails WHERE username = ?",
    [username],
    (err, result) => {
      if (err) console.log(err);
      if (result.length > 0) {
        Object.keys(result).forEach(async function (key) {
          var row = result[key];
          const row1= row.password;
          const isValid = await bcrypt.compare(password, row1);
          if (isValid) {
            res.send(result);
            console.log("match!!");
          }
          else{
            console.log("incorrect password");
            res.send({message: "wrong username or password"});
          }
        });
      } else {
        console.log("wrong username!");
        res.send({ message: "wrong username or password" });
      }
    }
  );
});

app.get("/", function (req, res) {
  res.send("hello");
});

app.listen(PORT, () => {
  db.connect((err) => {
    if (!err) console.log("database connected..");
    else
      console.log(
        "db not connected \n Error : " + JSON.stringify(err, undefined, 2)
      );
  });
  console.log(`Server is running on ${PORT}`);
});
