import { useState } from "react";
import Axios from "axios";

function Login() {
  const [usernameReg, setUsernameReg] = useState("");
  const [passwordReg, setPasswordReg] = useState("");

  const [usernameLogin, setUsernameLogin] = useState("");
  const [passwordLogin, setPasswordLogin] = useState("");

  const [userDisplay, setUserDisplay] = useState("");

  const reg = () => {
    Axios.post("http://localhost:3003/Reg", {
      username: usernameReg,
      password: passwordReg,
    }).then((Response) => {
      console.log(Response);
    });
  };

  const login = () => {
    Axios.post("http://localhost:3003/Login", {
      username: usernameLogin,
      password: passwordLogin,
    }).then((Response) => {
      if (Response.data.message) {
        alert(Response.data.message);
      } else {
        setUserDisplay(Response.data[0].username);
      }
      console.log(Response.data)
    });
  };

  return (
    <div className="LogRegMain">
      <div className="reg">
        <h1>REGISTER</h1>
        <label>Username</label>
        <input
          type="text"
          onChange={(e) => {
            // console.log("in");
            setUsernameReg(e.target.value);
          }}
        />
        <label>Password</label>
        <input
          type="password"
          onChange={(e) => {
            setPasswordReg(e.target.value);
          }}
        />
        <button onClick={reg}>submit</button>
      </div>

      <div className="login"></div>
      <h1>LOGIN</h1>
      <label>Username</label>
      <input
        type="text"
        onChange={(e) => {
          // console.log("in");
          setUsernameLogin(e.target.value);
        }}
      />
      <label>Password</label>
      <input
        type="password"
        onChange={(e) => {
          setPasswordLogin(e.target.value);
        }}
      />
      <button onClick={login}>submit</button>

      <h1>{userDisplay}</h1>
    </div>
  );
}

export default Login;
