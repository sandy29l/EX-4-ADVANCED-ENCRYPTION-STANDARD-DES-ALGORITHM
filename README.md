# EX-7-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM: 
```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint64_t stringToBinary(const char *str)
{
    uint64_t binary = 0;
    for (int i = 0; i < 8 && str[i] != '\0'; ++i)
    {
        binary <<= 8;
        binary |= (uint64_t)(unsigned char)str[i]; 
    }
    return binary;
}

uint32_t XOR(uint32_t a, uint32_t b)
{
    return a ^ b;
}

uint64_t encryptDES(uint64_t plainText)
{
    uint32_t left = (plainText >> 32) & 0xFFFFFFFF;
    uint32_t right = plainText & 0xFFFFFFFF;
    uint32_t xorResult = XOR(left, right);
    uint64_t cipherText = 0;
    cipherText = ((uint64_t)right << 32) | xorResult;
    return cipherText;
}

uint64_t decryptDES(uint64_t cipherText)
{
    uint32_t left = (cipherText >> 32) & 0xFFFFFFFF;
    uint32_t right = cipherText & 0xFFFFFFFF;
    uint32_t xorResult = XOR(left, right);
    uint64_t plainText = 0;
    plainText = ((uint64_t)xorResult << 32) | right; 
    return plainText;
}

void binaryToString(uint64_t binary, char *str)
{
    for (int i = 0; i < 8; i++)
    {
        str[i] = (binary >> (56 - i * 8)) & 0xFF; 
    }
    str[8] = '\0'; 
}

int main()
{
    char plainText[9];  
    printf("Enter an 8-character plaintext: ");
    fgets(plainText, sizeof(plainText), stdin);
    plainText[strcspn(plainText, "\n")] = 0;  

    // Ensure the input is exactly 8 characters
    if (strlen(plainText) != 8) {
        printf("Please enter exactly 8 characters.\n");
        return 1;
    }

    uint64_t binaryPlainText = stringToBinary(plainText);
    uint64_t cipherText = encryptDES(binaryPlainText);
    printf("Encrypted Cipher Text (in hex): %016llX\n", cipherText);

    uint64_t decryptedText = decryptDES(cipherText);
    char decryptedString[9];
    binaryToString(decryptedText, decryptedString);
    
    printf("Decrypted String: %s\n", decryptedString);
    return 0;
}
```
## OUTPUT:
![Screenshot 2024-10-27 214942](https://github.com/user-attachments/assets/fdf27811-276b-44cc-968e-cfb2817c867c)

## RESULT: 
Thus the data encryption standard algorithm had been implemented successfully.
