#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/** Encrypt a given plaintext using the Caesar cipher, with the specified shift.
  *
  * \param range_low The lower bound of the range (e.g., 'A')
  * \param range_high The upper bound of the range (e.g., 'Z')
  * \param shift The integer shift for the Caesar cipher
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored.
  *           The buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  */
void caesar_encrypt(char range_low, char range_high, int shift, const char *plain_text, char *cipher_text) {
    int i;
    int range_size = range_high - range_low + 1;
    for (i = 0; plain_text[i] != '\0'; ++i) {
        char plain_char = plain_text[i];
        if (plain_char >= range_low && plain_char <= range_high) {
            cipher_text[i] = range_low + (plain_char - range_low + shift) % range_size;
        } else {
            cipher_text[i] = plain_char;
        }
    }
    cipher_text[i] = '\0';
}

/** Decrypt a given ciphertext using the Caesar cipher, with the specified shift.
  *
  * \param range_low The lower bound of the range (e.g., 'A')
  * \param range_high The upper bound of the range (e.g., 'Z')
  * \param shift The integer shift for the Caesar cipher
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored.
  *           The buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  */
void caesar_decrypt(char range_low, char range_high, int shift, const char *cipher_text, char *plain_text) {
    caesar_encrypt(range_low, range_high, (range_high - range_low + 1) - shift, cipher_text, plain_text);
}

/** Encrypt a given plaintext using the Vigenere cipher, using a specified key, where the
  * characters to encrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           encrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param plain_text A null-terminated string containing the plaintext to be encrypted
  * \param cipher_text A pointer to a buffer where the encrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           plain_text (including the terminating null character).
  */
void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text) {
    int key_len = strlen(key);
    int key_index = 0;

    for (int i = 0; plain_text[i] != '\0'; ++i) {
        char plain_char = plain_text[i];

        if (plain_char >= range_low && plain_char <= range_high) {
            char key_char = key[key_index % key_len];
            cipher_text[i] = range_low + (plain_char - range_low + key_char - range_low) % (range_high - range_low + 1);
            key_index++;
        } else {
            cipher_text[i] = plain_char;
        }
    }

    cipher_text[strlen(plain_text)] = '\0';
}

/** Decrypt a given ciphertext using the Vigenere cipher, using a specified key, where the
  * characters to decrypt fall within a given range (and all other characters are copied
  * over unchanged).
  *
  * \param range_low A character representing the lower bound of the character range to be
  *           decrypted
  * \param range_high A character representing the upper bound of the character range
  * \param key A null-terminated string containing the encryption key
  * \param cipher_text A null-terminated string containing the ciphertext to be decrypted
  * \param plain_text A pointer to a buffer where the decrypted text will be stored. The
  *           buffer must be large enough to hold a C string of the same length as
  *           cipher_text (including the terminating null character).
  */
void vigenere_decrypt(char range_low, char range_high, const char *key,
                      const char *cipher_text, char *plain_text) {
    int key_len = strlen(key);
    int key_index = 0;

    for (int i = 0; cipher_text[i] != '\0'; ++i) {
        char cipher_char = cipher_text[i];

        if (cipher_char >= range_low && cipher_char <= range_high) {
            char key_char = key[key_index % key_len];
            plain_text[i] = range_low + (cipher_char - key_char + (range_high - range_low + 1)) % (range_high - range_low + 1);
            key_index++;
        } else {
            plain_text[i] = cipher_char;
        }
    }

    plain_text[strlen(cipher_text)] = '\0';
}

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
            caesar_encrypt('A', 'Z', shift, message, output);
        } else {
            caesar_decrypt('A', 'Z', shift, message, output);
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

// Example main function for testing
int main(int argc, char **argv) {
    return cli(argc, argv);
}
#include "crypto.h"
#include <stdio.h> 
#include <string.h>
#include <assert.h>


/****************************************************************/
void caesar_encrypt(char range_low, char range_high, int key, const char * plain_text, char * cipher_text){
    /* Check which char are within the range 

        Eliminate chars less than the low range && Eliminate chars more than the high range 

        For loop to check characters are in the low range or high range 


    Storing the key value 
        
        Character Array of keys is stored as their ASCII value 
        
    Switch characters 

        Convert ASCII char into integer char 

        Difference between the two characters 

        Add difference to create the cipher text 

    Build plain text and store the plain text 

        Add the character to the buffers
    
    
    */
    int len = 0; 
    int low_value = (int) range_low;
    int high_value = (int) range_high; 

    printf("ASCII value of range_low: %i \n", low_value);

    printf("ASCII value of range_high: %i \n", high_value);

    

    for (int i = 0; i < strlen(plain_text); ++i){
        printf("Character : %c \n", plain_text[i]);
    
        int char_val = (int) plain_text[i];
        printf("Character value %d \n", char_val); 
        
        if (char_val < low_value || char_val > high_value){
            printf("Character is out of range \n");
            printf("Cipher char %c \n",(char) char_val );
            cipher_text[i] = (char) char_val;
        }else{ 
            char cipher_char = (char) (char_val + key);
            printf("Cipher character: %c \n", cipher_char);
            cipher_text[i] = cipher_char;
        }



    }

        


} 




void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    int len = strlen(cipher_text);
    int range_size = range_high - range_low + 1;
    printf("decrypting");
    

    for (int i = 0; i < len; ++i) {
        printf("Character in cipher text %c \n", cipher_text[i]);

        int char_val = (int) cipher_text[i];

        if (char_val < range_low || char_val > range_high) {
            plain_text[i] = cipher_text[i];
        } else {
            int new_char_val = char_val - key;
            while (new_char_val < range_low) {
                new_char_val = range_high - (range_low - new_char_val - 1);
            }
            plain_text[i] = (char) new_char_val;
        }
        printf("Character in plain text %c \n", plain_text[i]);
    }
    plain_text[len] = '\0'; // Null-terminate the plain_text
}

// Helper function to perform Vigenere encryption on a single character
char vigenere_encrypt_char(char plain_char, char key_char, char range_low, char range_high) {
    int range_size = range_high - range_low + 1;
    return range_low + (plain_char - range_low + key_char - range_low) % range_size;
}

void vigenere_encrypt(char range_low, char range_high, const char *key,
                      const char *plain_text, char *cipher_text) {
    // Get the length of the key
    int key_len = strlen(key);
    // Initialize the index for the key
    int key_index = 0;
    
    // Iterate over each character in the plain_text
    for (int i = 0; plain_text[i] != '\0'; ++i) {
        char plain_char = plain_text[i];
        
        // Check if the character is within the specified range
        if (plain_char >= range_low && plain_char <= range_high) {
            // Get the current key character
            char key_char = key[key_index % key_len];
            // Encrypt the character and store it in cipher_text
            cipher_text[i] = vigenere_encrypt_char(plain_char, key_char, range_low, range_high);
            // Move to the next key character
            key_index++;
        } else {
            // Copy the character as is if it's out of range
            cipher_text[i] = plain_char;
        }
    }
    
    // Null-terminate the cipher_text
    cipher_text[strlen(plain_text)] = '\0';
}
char vigenere_decrypt_char(char cipher_char, char key_char, char range_low, char range_high) {
    int range_size = range_high - range_low + 1;
    return range_low + (cipher_char - key_char + range_size) % range_size;
}

void vigenere_decrypt(char range_low, char range_high, const char *key,
                      const char *cipher_text, char *plain_text) {
    // Get the length of the key
    int key_len = strlen(key);
    // Initialize the index for the key
    int key_index = 0;
    
    // Iterate over each character in the cipher_text
    for (int i = 0; cipher_text[i] != '\0'; ++i) {
        char cipher_char = cipher_text[i];
        
        // Check if the character is within the specified range
        if (cipher_char >= range_low && cipher_char <= range_high) {
            // Get the current key character
            char key_char = key[key_index % key_len];
            // Decrypt the character and store it in plain_text
            plain_text[i] = vigenere_decrypt_char(cipher_char, key_char, range_low, range_high);
            // Move to the next key character
            key_index++;
        } else {
            // Copy the character as is if it's out of range
            plain_text[i] = cipher_char;
        }
    }
    
    // Null-terminate the plain_text
    plain_text[strlen(cipher_text)] = '\0';
}

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

int main(){ 
    char plain_text[] = "HELLOWORLD";
    char cipher_text[sizeof(plain_text)] = {0};
    caesar_encrypt('A', 'Z', 3, plain_text, cipher_text);
    char* expected_cipher_text = "KHOORZRUOG";
    //assert(strcmp(cipher_text, expected_cipher_text) == 0);
    char plain_text2[sizeof(cipher_text)] = {0};
    caesar_decrypt('A', 'Z', 3, cipher_text, plain_text2);
}