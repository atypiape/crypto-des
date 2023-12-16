import CryptoJS from '../core';

(function (undefined) {
    // Shortcuts
    var C = CryptoJS;
    var C_lib = C.lib;
    var CipherParams = C_lib.CipherParams;
    var C_enc = C.enc;
    var Base64 = C_enc.Base64;
    var C_format = C.format;

    var Base64Formatter = C_format.Base64 = {
        /**
         * Converts the ciphertext of a cipher params object to a base64 encoded string.
         *
         * @param {CipherParams} cipherParams The cipher params object.
         *
         * @return {string} The base64 encoded string.
         *
         * @static
         *
         * @example
         *
         *     var base64String = CryptoJS.format.Base64.stringify(cipherParams);
         */
        stringify: function (cipherParams) {
            return cipherParams.ciphertext.toString(Base64);
        },

        /**
         * Converts a base64 encoded ciphertext string to a cipher params object.
         *
         * @param {string} input The base64 encoded string.
         *
         * @return {CipherParams} The cipher params object.
         *
         * @static
         *
         * @example
         *
         *     var cipherParams = CryptoJS.format.Base64.parse(base64String);
         */
        parse: function (input) {
            var ciphertext = Base64.parse(input);
            return CipherParams.create({ ciphertext: ciphertext });
        }
    };
}());
