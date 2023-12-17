import "./style.css";
import {
  DES,
  TripleDES,
  DESEncodingType,
  DESModeType,
  DESOptions,
  DESPaddingType,
  DESBase,
} from "../lib";

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>CryptoJS DES</h1>
    <div class='card'>
      <p class='read-the-docs'>
      CryptoJS is ${DES ? "defined" : "undefined"}
      </p>
    </div>
  </div>
`;

const key = "72c3c22abf65cd99fd9f6d97210eef8bd06ebe40a9e8e3dac693fa50630640";
const message = "Hello World"; //  | 你好 | Привет
const iv = "1234";

function des(
  algo: DESBase,
  mode: DESModeType,
  padding: DESPaddingType,
  encoding: DESEncodingType,
  isTriple: boolean = false
) {
  const kind = `${mode}-${padding}-${encoding}`;
  const options: DESOptions = {
    mode,
    padding,
    ciphertextEncoding: encoding,
    iv,
  };

  console.log(
    `-------------------${isTriple ? "Triple" : ""} ${kind} -------------------`
  );

  try {
    const encrypted = algo.encrypt(message, key, options);
    console.log(`encrypt:`, encrypted.toString());
    const decrypted = algo.decrypt(encrypted, key, options);
    console.log(`decrypt:`, decrypted.toString());
  } catch (e) {
    console.error(e);
  }

  console.log("\n");
}

(function () {
  const modes = Object.values(DES.mode);
  const paddings = Object.values(DES.pad);
  const encodings = Object.values(DES.enc);

  modes.forEach((mode) => {
    paddings.forEach((padding) => {
      encodings.forEach((encoding) => {
        des(DES, mode, padding, encoding);
        des(TripleDES, mode, padding, encoding, true);
      });
    });
  });
})();

const encrypted = DES.encrypt(message, key, {
  mode: DES.mode.CBC,
  padding: DES.pad.NoPadding,
  ciphertextEncoding: DES.enc.Base64,
  keyEncoding: DES.enc.Hex,
  iv,
});
console.log(`encrypt:`, encrypted.toString());
const decrypted = DES.decrypt(encrypted, key, {
  mode: DES.mode.CBC,
  padding: DES.pad.NoPadding,
  ciphertextEncoding: DES.enc.Base64,
  keyEncoding: DES.enc.Hex,
  iv,
});
console.log(`decrypt:`, decrypted.toString());