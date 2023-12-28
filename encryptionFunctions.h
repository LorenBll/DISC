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

char* genereate_encryptionSalt () {
    //. funzione che genera un sale di criptazione

    const char encryptionSaltAlphabet[] = "[{]}!@#$^&*()_+-=,./<>?;':|";
    srand( time(NULL) );

    char *encryptionSalt = (char*) malloc( sizeof(char) * ( 5 ) );

    for ( int i = 0 ; i < 5 ; i++ ) {
        encryptionSalt[i] = encryptionSaltAlphabet[rand() % ( sizeof(encryptionSaltAlphabet) - 1 )];
    }

    encryptionSalt[5] = '\0';

    return encryptionSalt;

}

void encrypt_string ( char *string , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che prende in input una stringa e la cripta

    int stringLength = strlen(string);
    int encryptionKeyLength = strlen(encryptionKey);

    for ( int i = 0 ; i < stringLength ; i++ ) {
        string[i] = string[i] ^ encryptionKey[i % encryptionKeyLength] ^ encryptionSalt[i % 5];
    }

    string[stringLength] = '\0';

}

void decrypt_string ( char *string , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che prende in input una stringa criptata e la decripta

    int stringLength = strlen(string);
    int encryptionKeyLength = strlen(encryptionKey);

    for ( int i = 0 ; i < stringLength ; i++ ) {
        string[i] = string[i] ^ encryptionKey[i % encryptionKeyLength] ^ encryptionSalt[i % 5];
    }

    string[stringLength] = '\0';

}