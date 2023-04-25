const bcrypt = require("bcrypt");
let db = require("../../database/db.json");
let fs = require("fs");
let path = require("path");
let { createAuthTokens } = require("../../helpers/tokenHelper");
const { Module } = require("module");

if (!fs.existsSync(path.join(__dirname, "../../database/db.json"))) {
  //create new file if not exist
  fs.closeSync(
    fs.openSync(path.join(__dirname, "../../database/db.json")),
    "w"

  );
}

const register = async (req, res, next) => {
  let { username, password } = req.body;
  // user alredy exist
  const found = db.users.some((el) => el.username === username);
  if (found)
    return res
      .status(400)
      .send({ error: { message: "Username Alredy Exist" } });
  //  hashing password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  // defing new user
  let newUser = {
    id: db.users.length + 1,
    username: username,
    password: hashedPassword,
  };

  // adding new user in database
  db.users.push(newUser);
  fs.writeFileSync(
    path.join(__dirname, "../../database/db.json"),
    JSON.stringify(db)
  );

  // creating tokens

  const [token, refreshToken] = await createAuthTokens({
    user: { id: newUser.id, username: newUser.username },
    secret: process.env.ACCESS_TOKEN_SECRET,
    secret2: process.env.REFRESH_TOKEN_SECRET + newUser.password,
  });

  //  setting sessions

  res.cookie("refresh_token", refreshToken, {
    maxAge: 86_400_000,
    httpOnly: true,
  });

  res.header("refresh-token", refreshToken);
  res
    .header("auth-token", token)
    .send({
      status: "Success",
      payload: {
        user: {
          id: newUser.id,
          username: username,
          accessToken: token,
          refreshToken: refreshToken,
        },
      },
    });
};

const login = async (req, res, next) => {
  let { username, password } = req.body;

  const found = db.users.some((el) => el.username === username);
  if(!found) return res.status(400).send({error:{message:"Username or Password is wrong"}});

  let savedUser = db.users.find(user => user.username === username);
  var validPass = await bcrypt.compare(password, savedUser.password);

   if (!validPass) return res.status(400).send({ error:{ message: "username or password is wrong"}});

  const [token, refreshToken] = await createAuthTokens({
    user: { id: savedUser.id, username: savedUser.username },
    secret: process.env.ACCESS_TOKEN_SECRET,
    secret2: process.env.REFRESH_TOKEN_SECRET + savedUser.password,
  });

  //  setting sessions
  res.cookie("refresh_token", refreshToken, {
    maxAge: 86_400_000,
    httpOnly: true,
  });

  res.header("refresh-token", refreshToken);
  res
    .header("auth-token", token)
    .send({
      status: "Success",
      payload: {
        user: {
          id: savedUser.id,
          username: username,
          accessToken: token,
          refreshToken: refreshToken,
        },
      },
    });
};

const renewTokens = async (req, res, next) => {
        var refreshToken = req.cookies.refresh_token;
        if (!refreshToken) return res.status(401).send({ status: "Fail", message: "Unauthorize acecsss" });
        const { id, username } = jwt.decode(refreshToken);

        if (!id) return res.status(401).send({ status: "Fail", message: "Unauthorize acecsss" });

        let savedUser = db.users.find(user => user.username === username);

        if (!savedUser) return res.status(401).send({ status: "Fail", message: "Unauthorize acecsss" })

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET + savedUser.password);

        const [newToken, newRefreshToken] = await createAuthTokens({
            user: {
                id: savedUser.id, username:savedUser.username
            }
            , secret: process.env.ACCESS_TOKEN_SECRET, secret2: process.env.REFRESH_TOKEN_SECRET + savedUser.password
        });
        res.cookie('refresh_token', newRefreshToken, {
            maxAge: 86_400_000,
            httpOnly: true,
        });

        res.header('refresh-token', newRefreshToken);
        res.header('auth-token', newToken).send({ status: "Success", payload: { user: { _id: userInDb._id, type: userInDb.type, email: userInDb.email, company: userInDb.company, accessToken: newToken, refreshToken: newRefreshToken } } });
      }


const logout = (req, res ,next) => {
    try {
        res.clearCookie('refresh_token');
        res.send({ status: "Success", message: "LogedOut Sucessfully" });
    } catch (error) {
        console.log(error);
        res.send(400).send({ payload: { error }, status: "Fail", message: "Something Went Wrong" });
    }
}


module.exports.login = login;
module.exports.register = register;
module.exports.logout = logout;
module.exports.renewTokens = renewTokens;
