import CryptoJS from "./core/index";
import "./enc";
import "./mode";
import "./pad";
import "./des";

type DESModeType = "ECB" | "CBC" | "CFB" | "OFB" | "CTR";

type DESPaddingType =
  | "Pkcs7"
  | "ZeroPadding"
  | "NoPadding"
  | "Iso10126"
  | "Iso97971"
  | "AnsiX923";

type DESEncodingType = "utf8" | "hex" | "base64";

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
  iv?: string;

  /**
   * The ciphertext encoding scheme, default is `hex`.
   * @example
   * { encoding: DES.enc.Base64 }
   * or
   * { encoding: 'base64' }
   */
  encoding?: DESEncodingType | DESEncoding;
}

export class DES {
  public static readonly mode = DESMode;

  public static readonly pad = DESPadding;

  public static readonly enc = DESEncoding;

  /**
   * Encrypts the given message using the given key and options.
   * @param {string} message The message to encrypt.
   * @param {string} key The key to use for encryption.
   * @param {DESOptions} options The options to use for encryption.
   * @returns {string} The encrypted message.
   */
  public static encrypt(
    message: string,
    key: string,
    options: DESOptions
  ): string {
    const encrypted = CryptoJS.DES.encrypt(
      message,
      CryptoJS.enc.Utf8.parse(key),
      {
        mode: DES.getMode(options.mode),
        padding: DES.getPadding(options.padding),
        iv: options.iv ? CryptoJS.enc.Utf8.parse(options.iv) : undefined,
      }
    );

    if (!options.encoding || options.encoding === "hex") {
      return CryptoJS.enc.Hex.stringify(encrypted.ciphertext);
    }

    if (options.encoding === "base64") {
      return CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
    }

    throw new Error(`[DES] Invalid 'encoding' (${options.encoding})`);
  }

  /**
   * Decrypts a ciphertext using the given key and options.
   * @param {string} ciphertext The ciphertext to decrypt.
   * @param {string} key The key to use for decryption.
   * @param {DESDecryptOptions} options The options to use for decryption.
   * @returns The decrypted ciphertext.
   */
  public static decrypt(
    ciphertext: string,
    key: string,
    options: DESOptions
  ): string {
    const decrypted = CryptoJS.DES.decrypt(
      ciphertext,
      CryptoJS.enc.Utf8.parse(key),
      {
        mode: DES.getMode(options.mode),
        padding: DES.getPadding(options.padding),
        iv: options.iv ? CryptoJS.enc.Utf8.parse(options.iv) : undefined,
        format: DES.getFormat(options.encoding),
      }
    );

    return decrypted.toString(CryptoJS.enc.Utf8);
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
      throw new Error(`[DES] Decrypt - Invalid 'encoding' '${encoding}'`);
    }
  }
}
