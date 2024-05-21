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
            char cipher_char = (int) (char_val + key);
            printf("Cipher character: %c \n", cipher_char);
            cipher_text[i] = cipher_char;
        }



    }

        


} 




void caesar_decrypt(char range_low, char range_high, int key, const char *cipher_text, char *plain_text) {
    int len = strlen(cipher_text);
    int range_size = range_high - range_low + 1;

    for (int i = 0; i < len; ++i) {
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
        printf("%d",plain_text[i]);
    }
    plain_text[len] = '\0'; // Null-terminate the plain_text
}

int main(){ 
    char plain_text[] = "HELLOWORLD";
    char cipher_text[sizeof(plain_text)] = {0};
    caesar_encrypt('A', 'Z', 3, plain_text, cipher_text);
    char* expected_cipher_text = "KHOORZRUOG";
    assert(strcmp(cipher_text, expected_cipher_text) == 0);
    char plain_text2[sizeof(cipher_text)] = {0};
    caesar_decrypt('A', 'Z', 3, cipher_text, plain_text2);
}