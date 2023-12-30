#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include <pcap.h>






//! === CONSTANTS, STRUCTURES AND ENUMS ===
#define ETHER_ADDR_LEN 6    // gli indirizzi MAC sono lunghi 6 byte
#define ETHER_ETYP_LEN 2    // il campo EtherType è lungo 2 byte
#define ETHER_HEAD_LEN 14   // l'header Ethernet è lungo 14 byte

#define packetHeader struct pcap_pkthdr

typedef struct mac_address {
    u_char addressBytes[ETHER_ADDR_LEN];
} mac_address;

typedef struct availableInterlocutor {
    char name[50];
    mac_address address;
} availableInterlocutor;

typedef struct availableInterlocutorsList {
    availableInterlocutor interlocutor;
    struct availableInterlocutorsList *next;
} availableInterlocutorsList;



mac_address ssapAddress;                                        // indirizzo MAC del SSAP ( il mio indirizzo MAC )
mac_address dsap_address;                                       // indirizzo MAC del DSAP ( il MAC della scheda di rete del destinatario )
availableInterlocutorsList *availableInterlocutorsHead = NULL;  // lista dei dispositivi che hanno inviato RTCS
availableInterlocutor myInterlocutor;                           // interlocutore scelto dall'utente

char *encryptionKey;    // chiave di criptazione
char *encryptionSalt;   // sale di criptazione

typedef enum boolean {
    FALSE = 0,
    TRUE = 1
} boolean;






//! === ENCRYPTION SECTION ===
void generate_encryptionKey ( char *encryptionKeyStorage , int encryptionKeyLength ) {
    //. funzione che genera una chiave di criptazione

    const char encryptionKeyAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand( time(NULL) );

    for ( int i = 0 ; i < encryptionKeyLength ; i++ ) {
        encryptionKeyStorage[i] = encryptionKeyAlphabet[rand() % ( sizeof(encryptionKeyAlphabet) - 1 )];
    }

    encryptionKeyStorage[encryptionKeyLength] = '\0';

}

void generate_encryptionSalt ( char *encryptionSaltStorage ) {
    //. funzione che genera un sale di criptazione

    const char encryptionSaltAlphabet[] = "[{]}!@#$^&*()_+-=,./<>?;':|";
    srand( time(NULL) );

    for ( int i = 0 ; i < 5 ; i++ ) {
        encryptionSaltStorage[i] = encryptionSaltAlphabet[rand() % ( sizeof(encryptionSaltAlphabet) - 1 )];
    }

    encryptionSaltStorage[5] = '\0';

}



void encrypt_string ( char *encryptionStorage , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che cripta una stringa

    int stringToEncryptLength = strlen( encryptionStorage );
    int encryptionKeyLength = strlen( encryptionKey );
    int encryptionSaltLength = strlen( encryptionSalt );

    int i = 0 , j = 0 , k = 0;

    while ( i < stringToEncryptLength ) {
        
        encryptionStorage[i] = encryptionStorage[i] ^ encryptionKey[j] ^ encryptionSalt[k];

        i++; j++; k++;

        // in questo modo se la chiave di criptazione è più corta della stringa da criptare, la chiave viene ripetuta
        if ( j == encryptionKeyLength )
            j = 0;
        if ( k == encryptionSaltLength )
            k = 0;
    
    }

}

void decrypt_string ( char *encryptionStorage , char *encryptionKey , char *encryptionSalt ) {
    //. funzione che decripta una stringa

    int stringToDecryptLength = strlen( encryptionStorage );
    int encryptionKeyLength = strlen( encryptionKey );
    int encryptionSaltLength = strlen( encryptionSalt );

    int i = 0 , j = 0 , k = 0;

    while ( i < stringToDecryptLength ) {
        
        encryptionStorage[i] = encryptionStorage[i] ^ encryptionKey[j] ^ encryptionSalt[k];

        i++; j++; k++;

        // in questo modo se la chiave di criptazione è più corta della stringa da criptare, la chiave viene ripetuta
        if ( j == encryptionKeyLength )
            j = 0;
        if ( k == encryptionSaltLength )
            k = 0;
    
    }

}






//! === ADDRESS SETTING SECTION ===
void set_ssapAddress ( char *nicName ) {
    //. funzione che imposta l'indirizzo MAC del SSAP

    pcap_if_t *nicList;
    char errorBuffer[PCAP_ERRBUF_SIZE+1];
    
    // ottengo la lista delle NIC
    if ( pcap_findalldevs(&nicList , errorBuffer) == -1 ) {
        fprintf( stderr , "Error in pcap_findalldevs: %s\n" , errorBuffer );
        exit(1);
    }

    // cerco la NIC con il nome specificato
    pcap_if_t *currentDevice;
    for ( currentDevice=nicList ; currentDevice ; currentDevice=currentDevice->next )
        if ( strcmp(currentDevice->name , nicName) == 0 )
            break;

    // se non ho trovato la NIC con il nome specificato, allora esco
    if ( currentDevice == NULL ) {
        fprintf( stderr , "Error: NIC not found. Restart the program." );
        Sleep(10000); // 10 secondi
        exit(1);
    }

    // copio l'indirizzo MAC della NIC nella variabile globale ssapAddress
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        ssapAddress.addressBytes[i] = currentDevice->addresses->addr->sa_data[i];

    // libero la memoria allocata per la lista delle NIC
    pcap_freealldevs(nicList);

}

void set_dsapAddress ( u_char *addressBytes ) {
    //. funzione che imposta l'indirizzo MAC del DSAP
    
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        dsapAddress.addressBytes[i] = addressBytes[i];

}






//! === NIC SETTING SECTION ===
void list_availableNICs () {
    //. funzione che elenca le NICs (network interface cards) disponibili

    pcap_if_t *nicList;
    char errorBuffer[PCAP_ERRBUF_SIZE+1];
    
    // ottengo la lista delle NIC
    if ( pcap_findalldevs(&nicList , errorBuffer) == -1 ) {
        fprintf( stderr , "Error in pcap_findalldevs: %s\n" , errorBuffer );
        Sleep(10000); // 10 secondi
        exit(1);
    }

    // stampo il nome e la descrizione di ogni NIC
    for ( pcap_if_t *currentDevice=nicList ; currentDevice ; currentDevice=currentDevice->next ) {
    
        // stampa delle informazioni "basiche"
        printf( "%s\n" , currentDevice->name );
        if ( currentDevice->description )
            printf( "\tDescription: %s\n" , currentDevice->description );

        printf("\n");
    
    }

    // libero la memoria allocata per la lista delle NIC
    pcap_freealldevs(nicList);

}

pcap_t *open_NIC ( char *nicName ) {
    //. funzione che apre la scheda di rete specificata

    char errorBuffer[PCAP_ERRBUF_SIZE+1];

    // apro la scheda di rete specificata in modalità promiscua
    pcap_t *nicHandle = pcap_open_live( nicName , 65536 , 1 , 60000 , errorBuffer );
    if ( nicHandle != NULL ) {
        set_ssapAddress(nicName);
        return nicHandle;
    }

    // gestisco l'eventuale errore
    fprintf( stderr , "\nUnable to open the adapter. %s is not supported by WinPcap\n" , nicName );
    Sleep(10000); // 10 secondi
    exit(1);

}

pcap_t *choose_NIC () {
    //. funzione che stampa le NIC disponibili e chiede all'utente di sceglierne una

    // stampo le NIC disponibili
    printf("Available NICs:\n");
    list_availableNICs();

    // chiedo all'utente di scegliere una NIC
    char nicName[200];
    printf("Choose a NIC: ");
    fgets( nicName , 200 , stdin );

    // setto il terminatore al posto del carattere di newline
    for ( int i=0 ; i<200 ; i++ ) {
        if ( nicName[i] == '\n' ) {
            nicName[i] = '\0';
            break;
        }
    }

    // apro la NIC scelta e ne ritorno la handle
    return open_NIC(nicName);

}






//! === RTCS SENDING-RECEIVING SECTION ===
void broadcast_RTCS ( pcap_t *nicHandle ) {
    //. funzione che "broadcasta" una RTCS sulla rete locale

    u_char packet[500];
    
    // setto il DSAP a 0xFF ( il pacchetto deve essere broadcastato )
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = 0xff;

    // setto il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // setto l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // setto il primo byte a 0 ( per far riconoscere la RTCS )
    packet[14] = 0x00;

    // faccio scegliere all'utente il nome con cui i PC che ascoltano lo visualizzano
    char name[51]; // 50 caratteri + 1 per il terminatore
    printf("Choose a name (long between 10 and 50 characters): ");
    fgets( name , 51 , stdin );
    // controllo che il nome sia lungo almeno 10 caratteri e che non sia più lungo di 50 caratteri. Se non lo è, uso un nome di default
    if ( strlen(name) < 10 || strlen(name) > 50 )
        strcpy( name , "NoNameDevice\n" );

    // setto il nome ed il terminatore
    for ( int i=0 ; i<50 ; i++ ) {
        if ( name[i] == '\n' ) {
            packet[15+i] = '\0';
            break;
        }
        packet[15+i] = name[i];
    }

    // invio il pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestisco l'eventuale errore
    fprintf( stderr , "\nError sending the packet: %s. Restart the program." , pcap_geterr(nicHandle) );
    Sleep(10000); // 10 secondi
    exit(1);

}

void list_availableInterlocutors ( pcap_t *nicHandle ) {
    //. funzione che elenca i dispositivi che hanno inviato RTCS

    int readingResult;
    packetHeader *header;
    const u_char *packetData;
    boolean receivedRTCS = FALSE; // variabile che indica se ho ricevuto almeno una RTCS

    // variabili per un timer che interrompa l'ascolto dopo un certo tempo
    int milliseconds = 0 , trigger = 30000; // 30 secondi
    clock_t start = clock();

    while ( ((readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0) && (milliseconds<trigger) ) {
        if ( readingResult == 0 ) { // nessun pacchetto ricevuto
            printf("Timeout expired. Restart the program.\n");
            Sleep(10000); // 10 secondi
            exit(1);
        }

        // aggiorno il timer
        clock_t difference = clock() - start;
        milliseconds = difference * 1000 / CLOCKS_PER_SEC;



        //. controlli sulla validità del pacchetto
        // controllo che il pacchetto ricevuto sia un RTCS
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x00 )
            continue;



        //. operazioni da eseguire se il pacchetto è valido
        receivedRTCS = TRUE;
        // stampo il nome e il MAC del dispositivo che ha broadcastato la RTCS
        printf( "%s : " , packetData+15 );
        for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        
            printf( "%02x" , packetData[i+6] );
            if ( i != ETHER_ADDR_LEN-1 )
                printf( ":" );

        }
        printf( "\n" );

        // aggiungo il dispositivo alla lista dei dispositivi disponibili ( in testa )
        availableInterlocutorsList *newInterlocutor = malloc( sizeof(availableInterlocutorsList) );
        for ( int i=0 ; i<50 ; i++ ) {

            if ( packetData[i+15] == '\0' ) {
                newInterlocutor->interlocutor.name[i] = '\0';
                break;
            }
            newInterlocutor->interlocutor.name[i] = packetData[i+15];
        
        }
        
        // copio l'indirizzo MAC del dispositivo
        for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
            newInterlocutor->interlocutor.address.addressBytes[i] = packetData[i+ETHER_ADDR_LEN];
        
        // aggiorno la lista
        newInterlocutor->next = availableInterlocutorsHead;
        availableInterlocutorsHead = newInterlocutor;

    }

    if ( receivedRTCS == FALSE ) {
        printf("No RTCS has been received. Restart the program.\n");
        Sleep(10000); // 10 secondi
        exit(1);
    }

}

void choose_availableInterlocutor () {
    //. funzione che chiede all'utente di scegliere un dispositivo tra quelli disponibili

    list_availableInterlocutors();

    // chiedo all'utente di scegliere un interlocutore in base al MAC address (è sicuramente univoco)
    char chosenAddressString[18];
    printf("Choose a device (by MAC address): ");
    fgets( chosenAddressString , 18 , stdin );

    // setto il terminatore al posto del carattere di newline
    for ( int i=0 ; i<18 ; i++ ) {
        if ( chosenAddressString[i] == '\n' ) {
            chosenAddressString[i] = '\0';
            break;
        }
    }

    // converto la stringa in un indirizzo MAC
    mac_address chosenAddress;
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        sscanf( chosenAddressString+3*i , "%02x" , &chosenAddress.addressBytes[i] );
    }
        
    // cerco il dispositivo scelto nella lista dei dispositivi disponibili
    availableInterlocutorsList *currentInterlocutor;
    for ( currentInterlocutor=availableInterlocutorsHead ; currentInterlocutor ; currentInterlocutor=currentInterlocutor->next ) {
        if ( memcmp( currentInterlocutor->interlocutor.address.addressBytes , chosenAddress.addressBytes , ETHER_ADDR_LEN ) == 0 )
            break;
    }

    // se non ho trovato il dispositivo scelto, allora esco
    if ( currentInterlocutor == NULL ) {
        fprintf( stderr , "\nError: device not found. Restart the program." );
        Sleep(10000); // 10 secondi
        exit(1);
    }

    // "ufficializzo" la scelta del dispositivo
    set_dsapAddress( currentInterlocutor->interlocutor.address.addressBytes );
    myInterlocutor = currentInterlocutor->interlocutor;
    SetConsoleTitle( myInterlocutor.name );

}






//! === STCS SENDING-RECEIVING SECTION ===
void send_STCS ( pcap_t *nicHandle ) {
    //. funzione che invia una STCS al dispositivo specificato

    u_char packet[500];
    
    // setto il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // setto il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // setto l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // setto il primo byte a 1 ( per far riconoscere la STCS )
    packet[14] = 0x01;

    // faccio scegliere all'utente il nome con cui l'interlocutore lo visualizzerà
    char name[51]; // 50 caratteri + 1 per il terminatore
    printf("Choose a name (long between 10 and 50 characters): ");
    fgets( name , 51 , stdin );

    // controllo che il nome sia lungo almeno 10 caratteri e che non sia più lungo di 50 caratteri. Se non lo è, uso un nome di default
    if ( strlen(name) < 10 || strlen(name) > 50 )
        strcpy( name , "NoNameDevice\n" );

    // setto il nome ed il terminatore
    for ( int i=0 ; i<50 ; i++ ) {
        if ( name[i] == '\n' ) {
            packet[15+i] = '\0';
            break;
        }
        packet[15+i] = name[i];
    }

    // invio del pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestione dell'eventuale errore
    fprintf( stderr , "\nError sending the packet: %s. Restart the program." , pcap_geterr(nicHandle) );
    Sleep(10000); // 10 secondi
    exit(1);

}

void receive_STCS ( pcap_t *nicHandle ) {
    //. funzione che attende una STCS

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    // variabili per un timer che interrompa l'ascolto dopo un certo tempo
    int milliseconds = 0 , trigger = 60000; // 60 secondi
    clock_t start = clock();

    while ( ((readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0) && (milliseconds<trigger) ) {
        if ( readingResult == 0 ) {
            printf("Timeout expired. Restart the program.\n");
            exit(0);
        }

        // aggiorno il timer
        clock_t difference = clock() - start;
        milliseconds = difference * 1000 / CLOCKS_PER_SEC;



        //. controlli sulla validità del pacchetto
        // controllo che il pacchetto sia di tipo STCS
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x01 )
            continue;

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;

        // controllo che il pacchetto sia stato inviato dal dispositivo scelto
        if ( memcmp( packetData+6 , dsapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;



        //. operazioni da eseguire se il pacchetto è valido
        // setto il DSAP al MAC del mittente
        set_dsapAddress( packetData+ETHER_ADDR_LEN );

        // copio il nome del mittente nelle variabili globali
        myInterlocutor.name = (char*) malloc( sizeof(char) * ( strlen(packetData+15) + 1 ) );
        strcpy( myInterlocutor.name , packetData+15 );
        myInterlocutor.address = dsapAddress;
        SetConsoleTitle( myInterlocutor.name );

        break;

    }

    if ( milliseconds >= trigger ) {
        printf("No STCS has been received. Restart the program.\n");
        Sleep(10000); // 10 secondi
        exit(1);
    }

}






//! === ENCRYPTION KEY SENDING-RECEIVING SECTION ===
void send_encryptionKey ( pcap_t *nicHandle ) {
    //. funzione che genera ed invia la chiave di criptazione (+ il sale)

    // genero la chiave di criptazione
    encryptionKey = (char*) malloc( sizeof(char) * ( 33 ) );
    generate_encryptionKey( encryptionKey , 33 );

    // genero il sale
    encryptionSalt = (char*) malloc( sizeof(char) * ( 5 ) );
    generate_encryptionSalt( encryptionSalt );



    // invio la chiave di criptazione
    u_char packet[500];
    
    // setto il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // setto il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // setto l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // setto il primo byte a 4 ( per far confondere la chiave di criptazione con un messaggio criptato)
    packet[14] = 0x04;

    // copio la chiave di criptazione nel pacchetto
    for ( int i=0 ; i<32 ; i++ )
        packet[15+i] = encryptionKey[i];

    // copio il sale nel pacchetto
    for ( int i=0 ; i<32 ; i++ )
        packet[47+i] = encryptionSalt[i];

    // invio il pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestione dell'eventuale errore
    fprintf( stderr , "\nError sending the packet: %s. Restart the program." , pcap_geterr(nicHandle) );
    Sleep(10000); // 10 secondi
    exit(1);

}

void receive_encryptionKey ( pcap_t *nicHandle ) {
    //. funzione che attende la chiave di criptazione (+ il sale) e la salva nelle apposite variabili globali

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    // variabili per un timer che interrompa l'ascolto dopo un certo tempo
    int milliseconds = 0 , trigger = 10000; // 10 secondi
    clock_t start = clock();

    while ( ((readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0) && (milliseconds<trigger) ) {
        if ( readingResult == 0 )
            printf("Timeout expired. Restart the program.\n");
            exit(1);
        }

        // aggiorno il timer
        clock_t difference = clock() - start;
        milliseconds = difference * 1000 / CLOCKS_PER_SEC;



        //. controlli sulla validità del pacchetto
        // controllo che il pacchetto sia di tipo messaggio
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x04 )
            continue;

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;

        // controllo che il pacchetto sia stato inviato dal dispositivo scelto
        if ( memcmp( packetData+6 , dsapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;



        //. operazioni da eseguire se il pacchetto è valido
        // copio la chiave di criptazione nelle variabili globali
        encryptionKey = (char*) malloc( sizeof(char) * ( 33 ) );
        for ( int i=0 ; i<32 ; i++ )
            encryptionKey[i] = packetData[15+i];

        // copio il sale nelle variabili globali
        encryptionSalt = (char*) malloc( sizeof(char) * ( 5 ) );
        for ( int i=0 ; i<4 ; i++ )
            encryptionSalt[i] = packetData[47+i];

        break;

    }

    if ( milliseconds >= trigger ) {
        printf("No encryption key has been received. Restart the program.\n");
        Sleep(10000); // 10 secondi
        exit(1);
    }

}   






//! === CHAT SECTION ===
void send_message ( pcap_t *nicHandle , char *message ) {
    //. funzione che invia un messaggio dopo averlo criptato

    u_char packet[500];

    // setto il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // setto il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];

    // setto l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // setto il primo byte a 4 ( per far riconoscere il messaggio )
    packet[14] = 0x04;

    // cripto il messaggio
    encrypt_string( message , encryptionKey , encryptionSalt );

    // copio il messaggio nel pacchetto
    for ( int i=0 ; i<strlen(message) ; i++ )
        packet[15+i] = message[i];

    // invio il pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestione dell'eventuale errore
    fprintf( stderr , "\nError sending the packet: %s. Restart the program." , pcap_geterr(nicHandle) );
    Sleep(10000); // 10 secondi
    exit(1);

}

void receiveAndPrint_message ( pcap_t *nicHandle ) {
    //. funzione che attende un messaggio e lo stampa dopo averlo decriptato

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    while ( (readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0 ) {
        if ( readingResult == 0 )
            continue;


            
        //. controlli sulla validità del pacchetto
        // controllo che il pacchetto sia di tipo messaggio
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x04 )
            continue;

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;

        // controllo che il pacchetto sia stato inviato dal dispositivo scelto
        if ( memcmp( packetData+6 , dsapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;



        //. operazioni da eseguire se il pacchetto è valido
        // decripto il messaggio
        char *decryptedMessage = (char*) malloc( sizeof(char) * ( strlen(packetData+15) + 1 ) );
        strcpy( decryptedMessage , packetData+15 );
        decrypt_string( decryptedMessage , encryptionKey , encryptionSalt );

        // stampo il messaggio
        printf( "%s : %s\n" , myInterlocutor.name , decryptedMessage );

        break;

    }

}






//! === CONNECTION MAINTENANCE SECTION ===
void send_closeConnectionPacket ( pcap_t *nicHandle ) {
    //. funzione che invia un pacchetto che comunica la chiusura della connessione

    u_char packet[500];

    // setto il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // setto il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];

    // setto l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // setto il primo byte a 5 ( per far riconoscere il pacchetto )
    packet[14] = 0x05;

    // invio il pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestione dell'eventuale errore
    exit(1);

}

void listen_closeConnectionPacket ( pcap_t *nicHandle ) {
    //. funzione che ascolta un pacchetto che comunica la chiusura della connessione

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    while ( (readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0 ) {
        if ( readingResult == 0 )
            continue;



        //. controlli sulla validità del pacchetto
        // controllo che il pacchetto sia di tipo closeConnection
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x05 )
            continue;

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;

        // controllo che il pacchetto sia stato inviato dal dispositivo scelto
        if ( memcmp( packetData+6 , dsapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 )
            continue;



        //. operazioni da eseguire se il pacchetto è valido
        printf("\r\n---\nThe connection has been closed by the other device.\n---\n");
        Sleep(10000); // 10 secondi
        exit(0);

    }

}






//! === MASTER & SLAVE CONNECTION ESTABLISHMENT ROUTINES ===
void cMaster_establish_connection ( pcap_t *nicHandle ) {
    //. funzione che stabilisce la connessione tra il cMaster ed il cSlave

    // handshake per stabilire la connessione
    myInterlocutor = choose_availableInterlocutor(); // scelta dell'interlocutore
    send_STCS( nicHandle ); // invio la StCS
    
    send_encryptionKey( nicHandle ); // invio la chiave di criptazione

}

void cSlave_establish_connection ( pcap_t *nicHandle ) {
    //. funzione che stabilisce la connessione tra il cSlave ed il cMaster

    // handshake per stabilire la connessione
    broadcast_RTCS( nicHandle ); // broadcast della RTCS
    receive_STCS( nicHandle ); // attesa della STCS

    receive_encryptionKey( nicHandle ); // attesa della chiave di criptazione

}

DWORD WINAPI checkout_connection ( void *data ) {
    //. funzione che controlla periodicamente se l'interlocutore ha inviato un closeConnectionPacket

    pcap_t *nicHandle = (pcap_t*) data;

    while (1) {
        listen_closeConnectionPacket( nicHandle );
        Sleep(5000); // 5 secondi
    }

}






//! === MAIN SECTION ===
void main () {

    atexit( send_closeConnectionPacket ); // invio un pacchetto che comunica la chiusura della connessione quando l'applicazione viene chiusa

    //. inizializzazione delle "impostazioni di partenza" comuni a cMaster e cSlave
    SetConsoleTitle("DISC");
    pcap_t *nicHandle = choose_NIC(); // scelta della NIC

    // chiedo se vuole essere cMaster o cSlave
    boolean isMaster = FALSE;
    char answer[2];
    printf("Do you want to choose your interlocutor? (y/n) ");
    fgets( answer , 2 , stdin );
    if ( answer[0] == 'y' || answer[0] == 'Y' ) {
        isMaster = TRUE;
    }



    //. esecuzione delle routine di connessione
    if ( isMaster )
        cMaster_establish_connection( nicHandle );
    else
        cSlave_establish_connection( nicHandle );

    //. faccio partire un thread che ascolta periodicamente se l'intelocutore ha inviato un closeConnectionPacket
    DWORD threadID;
    HANDLE threadHandle = CreateThread( NULL , 0 , checkout_connection , (void*) nicHandle , 0 , &threadID );
    if ( threadHandle == NULL ) {
        fprintf( stderr , "Error creating the thread used to maintain the connection. Restart the program.\n" );
        Sleep(10000); // 10 secondi
        exit(1);
    }

    printf("---\n"); // separazione tra la fase di connessione e la fase di chat

    //. esecuzione della chat
    if ( isMaster )
        while (1) {

            // invio di un messaggio
            char message[1000];
            printf("You : ");
            fgets( message , 1000 , stdin );
            send_message( nicHandle , message );

            // ricezione di un messaggio
            receiveAndPrint_message( nicHandle );
        
        }
    else
        while (1) {

            // ricezione di un messaggio
            receiveAndPrint_message( nicHandle );

            // invio di un messaggio
            char message[1000];
            printf("You : ");
            fgets( message , 1000 , stdin );
            send_message( nicHandle , message );
        
        }

}