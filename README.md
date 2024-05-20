# DISC

DISC stands for Decentralized Internal Safe Conversations. It is chat application, which doesn't need any server (**Decentralized**) which allows its users to communicate (**Conversations**) through encrypted messages (**Safe**), provided that they are on the same local network (**Internal**).

## Table of Contents

- [Warning/Disclaimer](#Warning/Disclaimer)
- [Getting Started](#Getting-Started)
- [Usage](#Usage)
- [Authors](#Authors)

## Warning/Disclaimer

DISC is a school project and much probably won't be developed any further. The goal of this specific project was to allow two users on the same local net to communicate privately. This project MUSTN'T be considered functioning (as it couldn't be tested), useful (it has no effective utility) or safe (the encryption method is reverse-engineerable).

## Getting Started

DISC requires the presence of Winpcap on the system. It can be downloaded from [here](https://www.winpcap.org/install/default.htm).

## Usage

DISC is a command line application. It must be compiled and then executed from the command line. At the start of the application you must specify the network interface (aka the network card) to use. After doing so you will be asked if you want to make yourself available to other devices (Conversation Slave) running DISC or be the one to choose the device to communicate with (Conversation Master).

If you are the **Conversation Master** you will be asked to choose the device to communicate with. After doing so you will be asked to insert the message to send. The message will be encrypted and sent to the other device. If you are the **Conversation Slave** you will be asked to wait for a message. When a message is received it will be decrypted and shown to you. After that you will be asked to insert the message to send. The message will be encrypted and sent to the other device. This cycle lasts until one of the two devices closes the application: when this happens the other device will be notified and the application will close.

## Authors

[LorenBll](https://github.com/LorenBll)
[LandiFigone777](https://github.com/LandiFigone777)