#ifndef CRYPTO_H
#define CRYPTO_H

/** Encrypt a given plaintext using the Caesar cipher, using a specified key, where the
  * characters to encrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Each character in `plain_text` is examined to see if it falls with the range specified
  * by `range_low` and `range_high`, and a corresponding character is then written to the
  * same position in `cipher_text`. If the `plain_text` character is outside the range,
  * then the corresponding character is not encrypted: exactly the same character should
  * be written to exactly the same position in `cipher_text`. If the `plain_text`
  * character is within the range, it should be encrypted using the Caesar cipher:  
  * a new character is obtained by shifting it by `key` positions (modulo the size of the
  * range).
  *
  * For decryption, use a negative key value or use the `caesar_decrypt` function with the
  * same key value.
  *
  *
  * ## Example usage
  *
  *
  *
  * ```c
  *   char plain_text[] = "HELLOWORLD";
  *   char cipher_text[sizeof(plain_text)] = {0};
  *   caesar_encrypt('A', 'Z', 3, plain_text, cipher_text);
  *   // After the function call, cipher_text will contain the encrypted text
  *   char expected_cipher_text = "KHOORZRUOG"
  *   assert(strcmp(cipher_text, expected_cipher_text) == 0);
  * ```
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key The encryption key
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  *
  * \pre `plain_text` must be a valid null-terminated C string
  * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must fall within range from 0 to `(range_high - range_low)`, inclusive.
  */
void caesar_encrypt(char range_low, char range_high, int key, const char * plain_text, char * cipher_text);

/** Decrypt a given ciphertext using the Caesar cipher, using a specified key, where the
  * characters to decrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Calling `caesar_decrypt` with some key $n$ is exactly equivalent to calling
  * `caesar_encrypt` with the key $-n$.
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key The encryption key
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  *
  * \pre `cipher_text` must be a valid null-terminated C string
  * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must fall within range from 0 to `(range_high - range_low)`, inclusive.
  */
void caesar_decrypt(char range_low, char range_high, int key, const char * cipher_text, char * plain_text);

/** Encrypt a given plaintext using the Vigenere cipher, using a specified key, where the
  * characters to encrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Each character in `plain_text` is examined to see if it falls with the range specified
  * by `range_low` and `range_high`, and a corresponding character is then written to the
  * same position in `cipher_text`. If the `plain_text` character is outside the range,
  * then the corresponding character is not encrypted: exactly the same character should
  * be written to exactly the same position in `cipher_text`. If the `plain_text`
  * character is within the range, it should be encrypted using the Vigenere cipher.
  * The function maintains an index into `key`, and uses the "current key character"
  * to encrypt. This index starts at position 0, and increments whenever an in-range
  * plaintext character is encountered. (In other words, out-of-range characters do
  * not result in a change of Caesar cipher.)
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  *
  * \pre `plain_text` must be a valid null-terminated C string
  * \pre `cipher_text` must point to a buffer of identical length to `plain_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must not be an empty string.
  */

void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text
);

/** Decrypt a given ciphertext using the Vigenere cipher, using a specified key, where the
  * characters to decrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * Calling `vigenere_decrypt` with some key $k$ should exactly reverse the operation of
  * `vigenere_encrypt` when called with the same key.
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           decrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  *
  * \pre `cipher_text` must be a valid null-terminated C string
  * \pre `plain_text` must point to a buffer of identical length to `cipher_text`
  * \pre `range_high` must be strictly greater than `range_low`.
  * \pre `key` must not be an empty string.
  */
void vigenere_decrypt(char range_low, char range_high, const char * key, const char * cipher_text, char * plain_text);

/** TODO
 */
/** Command Line Interface function for encryption and decryption.
  *
  * \param argc The number of arguments
  * \param argv An array of argument strings
  * \return 0 on success, 1 on failure
  */
int cli(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Error: Invalid number of arguments.\n");
        return 1;
    }

    const char *operation = argv[1];
    const char *key = argv[2];
    const char *message = argv[3];

    if (strcmp(operation, "caesar-encrypt") == 0 || strcmp(operation, "caesar-decrypt") == 0) {
        char *endptr;
        int shift = strtol(key, &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "Error: Invalid key for Caesar cipher. Must be an integer.\n");
            return 1;
        }

        char output[256];
        if (strcmp(operation, "caesar-encrypt") == 0) {
            caesar_encrypt(shift, message, output);
        } else {
            caesar_decrypt(shift, message, output);
        }
        printf("%s\n", output);
        return 0;

    } else if (strcmp(operation, "vigenere-encrypt") == 0 || strcmp(operation, "vigenere-decrypt") == 0) {
        char output[256];
        if (strcmp(operation, "vigenere-encrypt") == 0) {
            vigenere_encrypt('A', 'Z', key, message, output);
        } else {
            vigenere_decrypt('A', 'Z', key, message, output);
        }
        printf("%s\n", output);
        return 0;

    } else {
        fprintf(stderr, "Error: Invalid operation. Must be one of: caesar-encrypt, caesar-decrypt, vigenere-encrypt, vigenere-decrypt.\n");
        return 1;
    }
}

#endif
// CRYPTO_H
// vim: tw=90 :
