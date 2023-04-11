// import Image from "react-bootstrap/Image";
import Container from "react-bootstrap/esm/Container";
import banner from '../banner.jpg'

function Landing() {
  return (
    <div className="LandingPage">
      {/* <Image
        src={require("C:/Users/adity/OneDrive/Desktop/jewelWebBoot/yutkFrontEnd/src/banner.jpg")}
        height={290}
        width={1532}
      /> */}
      <Container>
        <img src={banner} className="img-fluid" />
      </Container>
    </div>
  );
}

export default Landing;
