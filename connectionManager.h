#include <stdio.h>
#include <pcap.h>
#include "encryptionFunctions.h"

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



mac_address ssapAddress; // indirizzo MAC del SSAP ( il mio indirizzo MAC )
mac_address dsap_address; // indirizzo MAC del DSAP ( il MAC della scheda di rete del destinatario )
availableInterlocutorsList *availableInterlocutorsHead = NULL; // lista dei dispositivi che hanno inviato RTCS

char *encryptionKey; // chiave di criptazione
char *encryptionSalt // sale di criptazione



//! === ADDRESS SETTING FUNCTIONS ===
void set_ssapAddress ( char *nicName ) {
    //. funzione che imposta l'indirizzo MAC del SSAP

    pcap_if_t *nicList;
    char errorBuffer[PCAP_ERRBUF_SIZE+1];
    
    // ottenimento della lista delle NIC
    if ( pcap_findalldevs(&nicList , errorBuffer) == -1 ) {
        fprintf( stderr , "Error in pcap_findalldevs: %s\n" , errorBuffer );
        exit(1);
    }

    // cerco la NIC con il nome specificato
    pcap_if_t *currentDevice;
    for ( currentDevice=nicList ; currentDevice ; currentDevice=currentDevice->next ) {
        if ( strcmp(currentDevice->name , nicName) == 0 )
            break;
    }

    // se non ho trovato la NIC con il nome specificato, allora esco
    if ( currentDevice == NULL ) {
        fprintf( stderr , "Error: NIC not found\n" );
        exit(1);
    }

    // copio l'indirizzo MAC della NIC nella variabile globale ssapAddress
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        ssapAddress.addressBytes[i] = currentDevice->addresses->addr->sa_data[i];
    }

    // libero la memoria allocata per la lista delle NIC
    pcap_freealldevs(nicList);

}

void set_dsapAddress ( u_char *packet ) {
    //. funzione che imposta l'indirizzo MAC del DSAP (un altro dispositivo) basandosi su un pacchetto ricevuto

    // copio l'indirizzo MAC del DSAP nella variabile globale dsapAddress
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        dsap_address.addressBytes[i] = packet[i+6];
    }

}






//! === NIC RELATED FUNCTIONS ===
void list_availableNICs () {
    //. funzione che elenca le NICs (network interface cards) disponibili

    pcap_if_t *nicList;
    char errorBuffer[PCAP_ERRBUF_SIZE+1];
    
    // ottenimento della lista delle NIC
    if ( pcap_findalldevs(&nicList , errorBuffer) == -1 ) {
        fprintf( stderr , "Error in pcap_findalldevs: %s\n" , errorBuffer );
        exit(1);
    }

    // stampo le informazioni relative alle NIC trovate : ci interessa solo il nome
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
    //. funzione che apre la scheda di rete specificata ritornandone la handle

    char errorBuffer[PCAP_ERRBUF_SIZE+1];

    // apertura della scheda di rete specificata in modalità promiscua
    pcap_t *nicHandle = pcap_open_live( nicName , 65536 , 1 , 60000 , errorBuffer );
    if ( nicHandle != NULL ) {
        set_ssapAddress(nicName);
        return nicHandle;
    }

    // gestione dell'eventuale errore
    fprintf( stderr , "\nUnable to open the adapter. %s is not supported by WinPcap\n" , nicName );
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






//! === RTCS RELATED FUNCTIONS ===
void broadcast_RTCS ( pcap_t *nicHandle ) {
    //. funzione che "broadcasta" una RTCS sulla rete locale

    u_char packet[500];
    
    // settaggio il DSAP a 0xFF ( il pacchetto deve essere broadcastato )
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = 0xff;

    // settaggio il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // settaggio l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // settaggio del primo byte a 0 ( per far riconoscere la RTCS )
    packet[14] = 0x00;

    // scelta del nome con cui i PC che ascoltano visualizzano il PC dell'utente
    char name[51]; // 50 caratteri + 1 per il terminatore
    printf("Choose a name (long between 10 and 50 characters): ");
    fgets( name , 51 , stdin );

    // settaggio del nome e del terminatore
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
    fprintf( stderr , "\nError sending the packet: %s\n" , pcap_geterr(nicHandle) );

}

void list_availableInterlocutors ( pcap_t *nicHandle ) {
    //. funzione che elenca i dispositivi che hanno inviato RTCS

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    while ( (readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0 ) {
        if ( readingResult == 0 )
            printf("Timeout expired. Restart the program\n");
            exit(0);

        // controllo che il pacchetto sia di tipo RTCS
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x00 ) {
            continue;
        }

        // stampo il nome e il MAC del dispositivo che ha broadcastato la RTCS
        printf( "%s : " , packetData+15 );
        for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        
            printf( "%02x" , packetData[i+6] );
            if ( i != ETHER_ADDR_LEN-1 )
                printf( ":" );

            // inserisco il dispositivo nella lista dei dispositivi disponibili
            availableInterlocutor newInterlocutor;
            strcpy( newInterlocutor.name , packetData+15 );
            for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
                newInterlocutor.address.addressBytes[i] = packetData[i+6];

            availableInterlocutorsList *newInterlocutorNode = malloc( sizeof(availableInterlocutorsList) );
            newInterlocutorNode->interlocutor = newInterlocutor;
            newInterlocutorNode->next = availableInterlocutorsHead;
            availableInterlocutorsHead = newInterlocutorNode;

        }
        printf( "\n" );

    }

}

availableInterlocutor choose_availableInterlocutor () {
    //. funzione che chiede all'utente di scegliere un dispositivo tra quelli disponibili

    list_availableInterlocutors();

    // chiedo all'utente di scegliere un dispositivo dal MAC address (è sicuramente univoco)
    mac_address chosenAddress;
    printf("Choose a device (MAC address): ");
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ ) {
        scanf( "%02x" , &chosenAddress.addressBytes[i] );
        if ( i != ETHER_ADDR_LEN-1 )
            scanf( ":" );
    }

    // cerco il dispositivo scelto nella lista dei dispositivi disponibili
    availableInterlocutorsList *currentInterlocutor;
    for ( currentInterlocutor=availableInterlocutorsHead ; currentInterlocutor ; currentInterlocutor=currentInterlocutor->next ) {
        if ( memcmp( currentInterlocutor->interlocutor.address.addressBytes , chosenAddress.addressBytes , ETHER_ADDR_LEN ) == 0 )
            break;
    }

    // se non ho trovato il dispositivo scelto, allora esco
    if ( currentInterlocutor == NULL ) {
        fprintf( stderr , "Error: device not found\n" );
        exit(1);
    }

    // ritorno il dispositivo scelto
    set_dsapAddress( currentInterlocutor->interlocutor.address.addressBytes );
    return currentInterlocutor->interlocutor;

}






//! === STCS RELATED FUNCTIONS ===
void send_STCS ( pcap_t *nicHandle , mac_address dsapAddress ) {
    //. funzione che invia una STCS al dispositivo specificato

    u_char packet[500];
    
    // settaggio il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // settaggio il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // settaggio l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // settaggio del primo byte a 1 ( per far riconoscere la STCS )
    packet[14] = 0x01;

    // settaggio del nome con cui i PC che ascoltano visualizzano il PC dell'utente
    char name[51]; // 50 caratteri + 1 per il terminatore
    printf("Choose a name (long between 10 and 50 characters): ");
    fgets( name , 51 , stdin );

    // settaggio del nome e del terminatore
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
    fprintf( stderr , "\nError sending the packet: %s\n" , pcap_geterr(nicHandle) );

}

void receive_STCS ( pcap_t *nicHandle ) {
    //. funzione che attende una STCS

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    while ( (readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0 ) {
        if ( readingResult == 0 )
            printf("Timeout expired. Restart the program\n");
            exit(0);

        // controllo che il pacchetto sia di tipo STCS
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x01 ) {
            continue;
        }

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 ) {
            continue;
        }

        // setto il DSAP al MAC del mittente
        set_dsapAddress( packetData+ETHER_ADDR_LEN );
        break;

    }

}






//! === ENCRYPTION KEY EXCHANGE FUNCTIONS ===
void send_encryptionKey ( pcap_t *nicHandle , mac_address dsapAddress ) {
    //. funzione che genera ed invia una chiave di criptazione (+ il sale) al dispositivo specificato

    // genero la chiave di criptazione
    encryptionKey = generate_encryptionKey();
    encryptionSalt = generate_encryptionSalt();

    // invio la chiave di criptazione
    u_char packet[500];
    
    // settaggio il DSAP al MAC del dispositivo specificato
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i] = dsapAddress.addressBytes[i];

    // settaggio il SSAP in modo tale che sia uguale al mio MAC
    for ( int i=0 ; i<ETHER_ADDR_LEN ; i++ )
        packet[i+ETHER_ADDR_LEN] = ssapAddress.addressBytes[i-ETHER_ADDR_LEN];
    
    // settaggio l'ethertype a quello usato per identificare l'applicazione
    packet[12] = 0x7a;
    packet[13] = 0xbc;

    // settaggio del primo byte a 2 ( per far riconoscere la chiave di criptazione )
    packet[14] = 0x02;

    // settaggio della chiave di criptazione
    for ( int i=0 ; i<32 ; i++ )
        packet[15+i] = encryptionKey[i];

    // settaggio del sale di criptazione
    for ( int i=0 ; i<32 ; i++ )
        packet[47+i] = encryptionSalt[i];

    // invio del pacchetto
    int sendingResult = pcap_sendpacket( nicHandle , packet , 500 );
    if ( sendingResult == 0 )
        return;

    // gestione dell'eventuale errore
    fprintf( stderr , "\nError sending the packet: %s\n" , pcap_geterr(nicHandle) );

}

void receive_encryptionKey ( pcap_t *nicHandle ) {
    //. funzione che attende una chiave di criptazione (+ il sale) dal dispositivo dsap e le salva nelle variabili globali relative

    int readingResult;
    packetHeader *header;
    const u_char *packetData;

    while ( (readingResult=pcap_next_ex( nicHandle , &header , &packetData )) >= 0 ) {
        if ( readingResult == 0 )
            printf("Timeout expired. Restart the program\n");
            exit(0);

        // controllo che il pacchetto sia di tipo chiave di criptazione
        if ( packetData[12] != 0x7a || packetData[13] != 0xbc || packetData[14] != 0x02 ) {
            continue;
        }

        // controllo che il pacchetto sia per me
        if ( memcmp( packetData , ssapAddress.addressBytes , ETHER_ADDR_LEN ) != 0 ) {
            continue;
        }

        // setto il DSAP al MAC del mittente
        set_dsapAddress( packetData+ETHER_ADDR_LEN );

        // salvo la chiave di criptazione
        encryptionKey = malloc( 33 * sizeof(char) );
        for ( int i=0 ; i<32 ; i++ )
            encryptionKey[i] = packetData[15+i];
        encryptionKey[32] = '\0';

        // salvo il sale di criptazione
        encryptionSalt = malloc( 33 * sizeof(char) );
        for ( int i=0 ; i<32 ; i++ )
            encryptionSalt[i] = packetData[47+i];
        encryptionSalt[32] = '\0';

        break;

    }

}






//! === MESSAGE EXCHANGE FUNCTIONS ===
