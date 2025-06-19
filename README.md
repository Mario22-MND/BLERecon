# BLERecon
This python script is used to automate some phases of the BSAM methodology, namely device discovery, information gathering, pairing analysis, and authentication and encryption analysis.  The first part of the script has a specific focus on compatibility with the Ubertooth-One device, while the second one parses captured BLE traffic from **.pcap** or **.pcapng** files. These tools aim to automate and facilitate the early stages of Bluetooth security assessment by providing enhanced visibility into nearby devices and their communication patterns.

Unlike conventional tools that rely only on capturing or performing Bluetooth attacks, this script aims to automate different phases of the BSAM methodology. The script is designed to be modular and extensible, allowing researchers and analysts to easily adapt it to different test scenarios or integrate it into security audit workflows. This is part of a master's thesis at the Carlos III University in Madrid.

The following section details the architecture of the script and its main functionalities. The script starts by displaying an interactive menu with two options, each of which corresponds to the automation of several specific phases within BSAM related to Bluetooth security analysis. These options are designed to simplify the user experience, while maintaining flexibility for different types of assessments.

## Main Menu 
![menu_global](https://github.com/user-attachments/assets/2a7c7445-4524-466e-8f9f-c98ed19c73c9)

The first menu option corresponds to phases 1 and 2 of BSAM, as the functions that have been automated within this option range from knowing the Bluetooth version of the devices, their name, the company that manufactures them to offering information about the signal strength and whether they use random MAC addresses.

### Menu for phases 1 and 2 of BSAM
![menu_fase1_2](https://github.com/user-attachments/assets/37a5203d-1bc0-4d04-a989-c3adfe094787)

Before analysing this submenu, it is important to clarify that for some of the implemented functions the Ubertooth-One tool is necessary because it uses its capture and scanning capabilities. These functionalities will be indicated with the text **(Ubertooth-one only)** at the end of their name.

Starting from the bottom, Option 4 launches a graphical spectrum analyzer for the 2.4 GHz ISM band using the **ubertooth-specan-ui** command. This feature provides a visual representation of signal strength across the Bluetooth frequency range, allowing the user to observe which channels are actively being used and detect the presence of nearby RF-emitting devices. This can be especially useful during the discovery phase of the BSAM methodology, as it offers a preliminary overview of the radio environment before proceeding with more detailed analysis.

Option 3 extends the device discovery process by combining active frequency scanning with device scanning via **ubertooth-scan -s -x** command. This command leverages both the Ubertooth-One and the BlueZ stack to detect nearby Bluetooth devices and gather relevant information. Upon selecting this option, the user is prompted to choose the desired output format:

1. Save results as a CSV file
2. Save results as a JSON file
3. Display results on screen (security features only)
4. Display results on screen in verbose mode

Unlike traditional tools such as **hcitool**, this feature enhances the scan by offering flexible output formats and introducing a basic security level classification for each detected device. The classification is based on the security-related features advertised by the device, and is categorized as follows:

- Low security: device only supports encryption and power control.
- Medium security: device supports Secure Simple Pairing (SSP) in addition to encryption.
- High security: device supports all previous features plus Secure Connections and other advanced capabilities.

This classification aims to provide a quick risk assessment of the surrounding Bluetooth environment, helping analysts prioritize which might be more vulnerable or worthy of deeper inspection. 

Option 2 is specifically designed for analyzing Bluetooth Low Energy (BLE) devices. It provides four functionalities, shown in the next Figure, that leverage the Ubertooth One device, in combination with tools such as Wireshark, to perform various forms of BLE sniffing, connection tracking, and post-capture analysis.

#### Sub-menu for BLE
![menu_fase1_2_BLE](https://github.com/user-attachments/assets/2ba48c11-0bc6-450b-a36f-35bc2145d079)

The first option of this BLE menu enables passive sniffing of BLE advertising packets using the Ubertooth command \textit{ubertooth-btle -n}. Piror to initiating the capture, the system prompts the user to select the preferred output format:

- DLT\_BLUETOOTH\_LE\_LL\_WITH\_PHDR: a format commonly supported by Wireshark, including physical layer headers
- DLT\_PPI + DLT\_BLUETOOTH\_LE\_LL: an alternative format using the PPI (Per-Packet Information) header for extended metadata

The resulting data can be directly visualized in Wireshark, allowing the inspection of device addresses (public or random), advertised service UUIDs, payloads, and beacon characteristics. This type of sniffing is essential for identifying nearby BLE devices and observing their advertising behavior.

The second option attempts to follow a specific BLE connection between two devices using the command **ubertooth-btle -f** or **ubertooth-btle -f -I**, depending on the user's choice. The system asks for a MAC address to follow, allowing the Ubertooth to focus on a specific device. The second command adds the option **-I** which when combined with **-f** will attempt to jam as many connections as it can. This flag functions as an easy, but not guaranteed, denial of service attack on in-range devices. These flags can be exploited to force devices to un-pair and re-pair so that the pairing event can be captured. This increases the probability of successfully capturing the pairing process, which is critical for analysing the BLE security configuration. Capturing the pairing process is complicated, as it requires the tracking device to be active during connection establishment.

The third functionality allows the capture of raw Bluetooth data using **ubertooth-dump -l**, the -l argument makes the command focus only on BLE. The command outputs a continuous stream of bits. These streams can be saved in .bin or .bbtbb formats. The last format can be later analyzed using libbtbb, a specialized library for decoding BLE packet structures from raw Ubertooth captures. This mode is particularly suitable for post-processing tasks, reverse engineering, or detailed research scenarios.

Last but not least, option 4 enables detailed analysis of previously captured BLE data stored in .pcap or .pcang files. The system extract the following information:

- All unique MAC addresses found in the capture
- The total number of packets sent by each device
- The types of PDU (Protocol Data Units)  transmitted such as ADV\_IND, CONNECT\_IND, SCAN\_REQ
- Device name and manufacturer information, if included in the payload

Option 1 from the main menu for phases 1 and 2 focuses on Bluetooth Classic. These functions are not yet worked on and will be left for possible work. 

### Menu for phases 3, 4 and 5 of BSAM

To support the analysis of Bluetooth Low Energy (BLE) security mechanisms, such as authentication and encryption, option 2 of the main menu was developed. Within this menu, a submenu shown in the next photo, opens with a function that aims to identify and interpret pairing procedures directly from raw packet capture files (**.pcap** or **.pcapng**). The tool allows automated extraction of critical security information, including the method of pairing, the use of LE secure connections and the presence or absence of authenticated encryption

![menu_fase3_4_5](https://github.com/user-attachments/assets/cab7766e-292a-4fcc-8668-e8f1110bfbbe)

The functionality begins by scanning the provided capture file for the presence of BLE Link Layer (LL) CONNECT\_IND packets (PDU type 0x05), which signal the establishment of a connection between the identified central and peripheral devices as part of a valid session. 

Next, the function attempts to extract and interpret LL\_VERSION\_IND packets, if present, in order to determine the Bluetooth version supported by each device. This is a relevant factor since the availability of LE Secure Connections is only supported from version 4.2.

Subsequently, the tool searches for packets associated with the Security Manager Protocol (SMP), specifically:

- Pairing Request
- Pairing Response

From these packets, the script obtains key fields that inform the matching process:

- IO Capabilities: Indicates the input and output capabilities of the device (e.g., DisplayOnly, KeyboardOnly). 
- OOB Data Flag: Indicates whether the packet contains data from an OOB authentication (e.g., OOB Auth. Data Not Present).
- Authentication Requirements (AuthReq), which includes:
    + MitM protection: To indicate whether the connection requires MitM protection
    + Bonding: To indicate whether the device allows to be bonded
    + Secure Connection support: To indicate whether or not the device supports Secure Connections

Combining these fields of the initiating (central or master) and responding (peripheral or slave) devices, the script detects the association model used during pairing (e.g. Just Works, Passkey Entry, Out-of-Band or Numeric Comparison) and the type of connection used (LE Legacy Pairing or LE Secure Connections). 

If present, the tool also processes the encryption-related packets, including the LL\_ENC\_REQ, LL\_ENC\_RSP and Encryption Information messages, to extract important values such as the long-term key (LTK) and the value to calculate it (Encrypted Diversifier (EDIV) and RAND values).

For each file, the output of the script is a summary that includes: 

- CONNECT\_IND packets: extracting information regarding both the initiator and the advertiser. It also indicates whether a pairing process was captured or not, as the mere presence of a \textit{CONNECT\_IND} packets does not guarantee that pairing has been captured.
- LL\_VERSION\_IND packets: which displays the company ID and Bluetooth version to retrieve information about the initiator and advertiser devices.
- Pairing Request/Response packets: which displays all the information necessary to then determine what type of connection and method of association the devices are using. This includes I/O capabilities, MitM Flag, secure connection flag, etc.
- LL\_ENC\_REQ / LL\_ENC\_RSP packets: values such as encrypted diversifier (EDIV) and random number (RAND) are displayed for these packets. These values are essential for the derivation and verification of the Long Term Key (LTK) used during the encryption process.
- Encryption information packet: this packet, if successfully captured during pairing, will display the value of the Long Term Key (LTK).

