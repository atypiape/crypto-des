declare interface Encoding {
  stringify: (message: string | WordArray) => string;
  parse: (message: string | WordArray) => WordArray;
}

declare interface WordArray {
  ciphertext: string;
  words: number[];
  sigBytes: number;
  toString: (encoding?: Encoding) => string;
}

declare interface Algorithm {
  encrypt(
    message: string | WordArray,
    key: string | WordArray,
    options: any
  ): WordArray;
  decrypt(
    ciphertext: string | WordArray,
    key: string | WordArray,
    options: any
  ): WordArray;
}

export declare const CryptoJS: {
  DES: Algorithm;
  TripleDES: Algorithm;

  enc: {
    Base64: Encoding;
    Utf8: Encoding;
    Hex: Encoding;
  };

  pad: {
    Pkcs7: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    NoPadding: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    Iso10126: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    Iso97971: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    ZeroPadding: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    ZeroUnpadding: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
    AnsiX923: {
      pad: (message: string, blockSize: number) => string;
      unpad: (message: string) => string;
    };
  };

  format: {
    Hex: {
      stringify: (message: string) => string;
      parse: (message: string) => string;
    };
    Base64: {
      stringify: (message: string) => string;
      parse: (message: string) => string;
    };
  };

  mode: {
    CBC: any;
    CFB: any;
    CTR: any;
    ECB: any;
    OFB: any;
  };

  cipherParams: {
    CBC: any;
    CFB: any;
    CTR: any;
    ECB: any;
    OFB: any;
  };

  lib: {
    WordArray: WordArray;
    BlockCipher: any;
    CipherParams: any;
  };
};

export default CryptoJS;
