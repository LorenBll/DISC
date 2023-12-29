#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



void genereate_encryptionKey ( char *encryptionKey , int encryptionKeyLength ) {
    //. funzione che genera una chiave di criptazione

    const char encryptionKeyAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand( time(NULL) );

    for ( int i = 0 ; i < encryptionKeyLength ; i++ ) {
        encryptionKey[i] = encryptionKeyAlphabet[rand() % ( sizeof(encryptionKeyAlphabet) - 1 )];
    }

    encryptionKey[encryptionKeyLength] = '\0';

}

void genereate_encryptionSalt ( char *encryptionSalt ) {
    //. funzione che genera un sale di criptazione

    const char encryptionSaltAlphabet[] = "[{]}!@#$^&*()_+-=,./<>?;':|";
    srand( time(NULL) );

    char *encryptionSalt = (char*) malloc( sizeof(char) * ( 5 ) );

    for ( int i = 0 ; i < 5 ; i++ ) {
        encryptionSalt[i] = encryptionSaltAlphabet[rand() % ( sizeof(encryptionSaltAlphabet) - 1 )];
    }

    encryptionSalt[5] = '\0';

}



void encrypt_string ( char *stringToEncrypt , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che cripta una stringa

    int stringToEncryptLength = strlen( stringToEncrypt );
    int encryptionKeyLength = strlen( encryptionKey );
    int encryptionSaltLength = strlen( encryptionSalt );

    char *encryptedString = (char*) malloc( sizeof(char) * ( stringToEncryptLength + encryptionKeyLength + encryptionSaltLength + 1 ) );

    int i = 0;
    int j = 0;
    int k = 0;

    // in questo modo se la chiave di criptazione è più corta della stringa da criptare, la chiave viene ripetuta
    while ( i < stringToEncryptLength ) {
        encryptedString[i] = stringToEncrypt[i] ^ encryptionKey[j] ^ encryptionSalt[k];

        i++;
        j++;
        k++;

        if ( j == encryptionKeyLength ) {
            j = 0;
        }

        if ( k == encryptionSaltLength ) {
            k = 0;
        }
    }

    encryptedString[stringToEncryptLength] = '\0';

    strcpy( stringToEncrypt , encryptedString );

    free( encryptedString );

}

void decrypt_string ( char *stringToDecrypt , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che decripta una stringa

    int stringToDecryptLength = strlen( stringToDecrypt );
    int encryptionKeyLength = strlen( encryptionKey );
    int encryptionSaltLength = strlen( encryptionSalt );

    char *decryptedString = (char*) malloc( sizeof(char) * ( stringToDecryptLength + encryptionKeyLength + encryptionSaltLength + 1 ) );

    int i = 0;
    int j = 0;
    int k = 0;

    // in questo modo se la chiave di criptazione è più corta della stringa da criptare, la chiave viene ripetuta
    while ( i < stringToDecryptLength ) {
        decryptedString[i] = stringToDecrypt[i] ^ encryptionKey[j] ^ encryptionSalt[k];

        i++;
        j++;
        k++;

        if ( j == encryptionKeyLength ) {
            j = 0;
        }

        if ( k == encryptionSaltLength ) {
            k = 0;
        }
    }

    decryptedString[stringToDecryptLength] = '\0';

    strcpy( stringToDecrypt , decryptedString );

    free( decryptedString );

}