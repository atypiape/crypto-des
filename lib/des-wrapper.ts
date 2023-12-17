import CryptoJS from "./core/index";
import "./enc";
import "./mode";
import "./pad";
import "./des";

interface Encoding {
  stringify: (message: string | WordArray) => string;
  parse: (message: string | WordArray) => WordArray;
}

interface WordArray {
  ciphertext: string;
  words: number[];
  sigBytes: number;
  toString: (encoding?: Encoding) => string;
}

interface Algorithm {
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

export type DESModeType = "ECB" | "CBC" | "CFB" | "OFB" | "CTR";

export type DESPaddingType =
  | "Pkcs7"
  | "ZeroPadding"
  | "NoPadding"
  | "Iso10126"
  | "Iso97971"
  | "AnsiX923";

export type DESEncodingType = "hex" | "base64";

enum DESMode {
  ECB = "ECB",
  CBC = "CBC",
  CFB = "CFB",
  OFB = "OFB",
  CTR = "CTR",
}

enum DESPadding {
  Pkcs7 = "Pkcs7",
  ZeroPadding = "ZeroPadding",
  NoPadding = "NoPadding",
  Iso10126 = "Iso10126",
  Iso97971 = "Iso97971",
  AnsiX923 = "AnsiX923",
}

enum DESEncoding {
  Base64 = "base64",
  Hex = "hex",
}

/**
 * DES encrypt/decrypt options
 * @typeof {DESOptions}
 * @property {string} mode - The mode of operation.
 * @property {string} pad - The padding scheme.
 * @property {string} [iv] - The initialization vector.
 */
export interface DESOptions {
  /**
   * The mode of operation.
   * @example
   * { mode: DES.mode.ECB }
   * or
   * { mode: 'ECB' }
   */
  mode: DESModeType | DESMode;

  /**
   * The padding scheme.
   * @example
   * { padding: DES.padding.Pkcs7 }
   * or
   * { padding: 'Pkcs7' }
   */
  padding: DESPaddingType | DESPadding;

  /** The initialization vector */
  iv?: string | WordArray;

  /**
   * The ciphertext encoding scheme, default is `hex`.
   * @example
   * { encoding: DES.enc.Base64 }
   * or
   * { encoding: 'base64' }
   */
  ciphertextEncoding?: DESEncodingType | DESEncoding;

  /**
   * The ciphertext encoding scheme, default is `utf8`.
   * @example
   * { encoding: DES.enc.Base64 }
   * or
   * { encoding: 'base64' }
   */
  keyEncoding?: DESEncodingType | DESEncoding;
}

export interface DESBase {
  encrypt(message: string, key: string, options: DESOptions): string | never;
  decrypt(ciphertext: string, key: string, options: DESOptions): string | never;
}

interface CryptoArgs {
  input: string;
  key: string;
  options: DESOptions;
}

abstract class DESImpl {
  public readonly mode = DESMode;

  public readonly pad = DESPadding;

  public readonly enc = DESEncoding;

  /**
   * Encrypts the given message using the given key and options.
   * @param {string} message - The message to encrypt.
   * @param {string} key - The key to use for encryption.
   * @param {DESOptions} options - The options to use for encryption.
   * @returns {string} The encrypted message.
   */
  protected static doEncrypt(
    algo: Algorithm,
    args: CryptoArgs
  ): string | never {
    const { input, key, options } = args;
    const { keyEncoding } = options;

    // 如果使用 NoPadding 填充方式进行加密，需要注意以下几点：
    // 1. 明文长度必须是 8 字节的倍数，否则加密过程会报错；
    // 2. 密钥和初始向量必须是 WordArray 对象，而不是字符串；
    // 3. 密文必须是 Base64 编码的字符串，而不是十六进制或其他格式的数据；
    if (options.padding === DESPadding.NoPadding) {
      const messageHex = CryptoJS.enc.Hex.stringify(
        CryptoJS.enc.Utf8.parse(args.input)
      );
      if (messageHex.length % 2 !== 0) {
        throw new Error("[DES] Input length not multiple of 8 bytes");
      }
    }

    const encrypted = algo.encrypt(input, DESImpl.encodeKey(key, keyEncoding), {
      mode: DESImpl.getMode(options.mode),
      padding: DESImpl.getPadding(options.padding),
      iv: CryptoJS.enc.Hex.parse(options.iv ?? ""),
    });

    const { ciphertextEncoding } = options;
    if (!ciphertextEncoding || ciphertextEncoding === DESEncoding.Hex) {
      return CryptoJS.enc.Hex.stringify(encrypted.ciphertext);
    }
    if (ciphertextEncoding === DESEncoding.Base64) {
      return CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
    }
    throw new Error(
      `[DES] Invalid 'ciphertextEncoding' (${ciphertextEncoding})`
    );
  }

  /**
   * Decrypts a ciphertext using the given key and options.
   * @param {string} ciphertext - The ciphertext to decrypt.
   * @param {string} key - The key to use for decryption.
   * @param {DESOptions} options - The options to use for decryption.
   * @returns {string} The decrypted ciphertext.
   */
  protected static doDecrypt(
    algo: Algorithm,
    args: CryptoArgs
  ): string | never {
    const { input, key, options } = args;
    const { keyEncoding, ciphertextEncoding } = options;

    CryptoJS.enc.Base64.parse(args.input);
    const decrypted = algo.decrypt(
      input,
      DESImpl.encodeKey(key, keyEncoding),
      {
        mode: DESImpl.getMode(options.mode),
        padding: DESImpl.getPadding(options.padding),
        iv: CryptoJS.enc.Hex.parse(options.iv ?? ""),
        format: DESImpl.getFormat(ciphertextEncoding),
      }
    );

    return decrypted.toString(CryptoJS.enc.Utf8);
  }

  private static encodeKey(key: string, encoding?: DESEncodingType): WordArray {
    switch (encoding) {
      case DESEncoding.Base64:
        return CryptoJS.enc.Base64.parse(key);
      case DESEncoding.Hex:
        return CryptoJS.enc.Hex.parse(key);
      default:
        break;
    }
    if (!encoding) {
      return CryptoJS.enc.Utf8.parse(key);
    } else {
      throw new Error(`[DES] Invalid 'keyEncoding' '${encoding}'`);
    }
  }

  private static getMode(mode: DESModeType) {
    switch (mode) {
      case DESMode.ECB:
        return CryptoJS.mode.ECB;
      case DESMode.CBC:
        return CryptoJS.mode.CBC;
      case DESMode.CFB:
        return CryptoJS.mode.CFB;
      case DESMode.OFB:
        return CryptoJS.mode.OFB;
      case DESMode.CTR:
        return CryptoJS.mode.CTR;
      default:
        throw new Error(`[DES] Invalid 'mode' (${mode})`);
    }
  }

  private static getPadding(padding: DESPaddingType) {
    switch (padding) {
      case DESPadding.Pkcs7:
        return CryptoJS.pad.Pkcs7;
      case DESPadding.ZeroPadding:
        return CryptoJS.pad.ZeroPadding;
      case DESPadding.NoPadding:
        return CryptoJS.pad.NoPadding;
      case DESPadding.Iso10126:
        return CryptoJS.pad.Iso10126;
      case DESPadding.Iso97971:
        return CryptoJS.pad.Iso97971;
      case DESPadding.AnsiX923:
        return CryptoJS.pad.AnsiX923;
      default:
        throw new Error(`[DES] Invalid 'padding' '${padding}'`);
    }
  }

  private static getFormat(encoding?: DESEncodingType) {
    switch (encoding) {
      case DESEncoding.Base64:
        return CryptoJS.format.Base64;
      case DESEncoding.Hex:
        return CryptoJS.format.Hex;
      default:
        break;
    }
    if (!encoding) {
      return CryptoJS.format.Hex;
    } else {
      throw new Error(`[DES] Invalid 'ciphertextEncoding' '${encoding}'`);
    }
  }
}

export const DES = new (class DES extends DESImpl implements DESBase {
  /**
   * Encrypts the given message using the given key and options.
   * @param {string} message - The message to encrypt.
   * @param {string} key - The key to use for encryption.
   * @param {DESOptions} options - The options to use for encryption.
   * @returns {string} - The encrypted message.
   */
  public encrypt(
    message: string,
    key: string,
    options: DESOptions
  ): string | never {
    return DESImpl.doEncrypt(CryptoJS.DES, { input: message, key, options });
  }

  /**
   * Decrypts a ciphertext using the given key and options.
   * @param {string} ciphertext - The ciphertext to decrypt.
   * @param {string} key - The key to use for decryption.
   * @param {DESOptions} options - The options to use for decryption.
   * @returns The decrypted ciphertext.
   */
  public decrypt(
    ciphertext: string,
    key: string,
    options: DESOptions
  ): string | never {
    return DESImpl.doDecrypt(CryptoJS.DES, { input: ciphertext, key, options });
  }
})();

export const TripleDES = new (class TripleDES
  extends DESImpl
  implements DESBase
{
  /**
   * Encrypts the given message using the given key and options.
   * @param {string} message - The message to encrypt.
   * @param {string} key - The key to use for encryption.
   * @param {DESOptions} options - The options to use for encryption.
   * @returns {string} - The encrypted message.
   */
  public encrypt(
    message: string,
    key: string,
    options: DESOptions
  ): string | never {
    return DESImpl.doEncrypt(CryptoJS.TripleDES, {
      input: message,
      key,
      options,
    });
  }

  /**
   * Decrypts a ciphertext using the given key and options.
   * @param {string} ciphertext - The ciphertext to decrypt.
   * @param {string} key - The key to use for decryption.
   * @param {DESOptions} options - The options to use for decryption.
   * @returns The decrypted ciphertext.
   */
  public decrypt(
    ciphertext: string,
    key: string,
    options: DESOptions
  ): string | never {
    return DESImpl.doDecrypt(CryptoJS.TripleDES, {
      input: ciphertext,
      key,
      options,
    });
  }
})();
