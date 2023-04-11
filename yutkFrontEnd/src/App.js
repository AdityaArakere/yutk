import { BrowserRouter, Routes, Route } from "react-router-dom";
import Landing from "./pages/LandingPage";
import Login from "./pages/LoginPage";
import NavBarFunc from "./components/NavbarComponent";

function App() {
  return (
    <>
    <BrowserRouter>
    <NavBarFunc />
      <Routes>
        <Route path="/" element={<Landing />}></Route>
        <Route path="/login" element={<Login />}></Route>
      </Routes>
    </BrowserRouter>
    </>
  );
}

export default App;

