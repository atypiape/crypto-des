import "./style.css";
import { DES, DESOptions } from "../dist";

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>CryptoJS DES</h1>
    <div class="card">
      <p class="read-the-docs">
      CryptoJS is ${DES ? "defined" : "undefined"}
      </p>
    </div>
  </div>
`;

const key = "AlVovFvcheqCGvkS2mojTILoFbhOjf1HFqGP9TAGAAq4";
const message = "Hello World | 你好 | Привет";

function des_ecb_pkcs7() {
  const options: DESOptions = {
    mode: DES.mode.ECB,
    padding: DES.pad.Pkcs7,
    encoding: DES.enc.Hex,
  };

  let encrypted = DES.encrypt(message, key, options);
  let decrypted = DES.decrypt(encrypted, key, options);
  console.log("encrypt [ECB-Pkcs7-Hex]:", encrypted.toString());
  console.log("decrypt [ECB-Pkcs7-Hex]:", decrypted.toString());

  options.encoding = DES.enc.Base64;
  encrypted = DES.encrypt(message, key, options);
  decrypted = DES.decrypt(encrypted, key, options);
  console.log("encrypt [ECB-Pkcs7-Base64]:", encrypted.toString());
  console.log("decrypt [ECB-Pkcs7-Base64]:", decrypted.toString());
}

function des_ecb_zero_padding() {
  const options: DESOptions = {
    mode: DES.mode.ECB,
    padding: DES.pad.ZeroPadding,
    encoding: DES.enc.Hex,
  };

  let encrypted = DES.encrypt(message, key, options);
  let decrypted = DES.decrypt(encrypted, key, options);
  console.log("encrypt [ECB-ZeroPadding-Hex]:", encrypted.toString());
  console.log("decrypt [ECB-ZeroPadding-Hex]:", decrypted.toString());

  options.encoding = DES.enc.Base64;
  encrypted = DES.encrypt(message, key, options);
  decrypted = DES.decrypt(encrypted, key, options);
  console.log("encrypt [ECB-ZeroPadding-Base64]:", encrypted.toString());
  console.log("decrypt [ECB-ZeroPadding-Base64]:", decrypted.toString());
}

(function () {
  des_ecb_pkcs7();
  des_ecb_zero_padding();
})();
