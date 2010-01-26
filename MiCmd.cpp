// MiCmd.cpp : Defines the entry point for the console application.
//
/*
* COPYLEFT Michal Boška aka Whitewash.
* This program is released under GPLv3 license ( http://www.gnu.org/licenses/gpl-3.0.txt )
*/


#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string>
#include <iostream>
#include <ios>
#include <sstream>
#include <ctype.h>
#include <math.h>

#ifdef WIN32
#include <windows.h>

#endif


extern "C" {
#include <nfc/nfc.h>
//#include <nfc/mifaretag.h>
}

using namespace std;

typedef unsigned char byte;
typedef unsigned int UINT;

typedef struct {
	bool c1,c2,c3;

} AccessCondition;

static nfc_device_t* pdi;
static nfc_target_info_t ti;
static mifare_param param;

const string VERSION = "0.011";

bool connected = false;
bool b4k;


void set_console_size() {
#ifdef WIN32

	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd,SW_MAXIMIZE);



#endif

}

byte* string_to_bytearray(string src, int* return_length)
{
	int length = src.length() / 2;
	byte* buffer = new byte[length];
	byte* ptr = buffer;

	*return_length = length;
	byte c1,c2;
	for (UINT i=0; i < src.length(); i += 2) {
		if ((src[i] >= '0') && (src[i] <= '9'))
			c1 = src[i] - '0';
		if ((src[i] >= 'a') && (src[i] <= 'f'))
			c1 = 10 + src[i] - 'a';
		if ((src[i] >= 'A') && (src[i] <= 'F'))
			c1 = 10 + src[i] - 'A';

		if ((src[i+1] >= '0') && (src[i+1] <= '9'))
			c2 = src[i+1] - '0';
		if ((src[i+1] >= 'a') && (src[i+1] <= 'f'))
			c2 = 10 + src[i+1] - 'a';
		if ((src[i+1] >= 'A') && (src[i+1] <= 'F'))
			c2 = 10 + src[i+1] - 'A';

		*ptr++ = c1*16 + c2;



	}
	return buffer;

}

string bytearray_to_string(byte* arr, int length, bool spacing=true) {
	string buffer = "";
	char table[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

	for (int i = 0; i < length; i++) {
		buffer.append(&(table[*arr / 16]), 1);
		buffer.append(&(table[*arr % 16]), 1);
		if (spacing)
			buffer.append(" ");
		arr++;

	}
	return buffer;



}

bool is_first_block(uint32_t uiBlock)
{
	// Test if we are in the small or big sectors
	if (uiBlock < 128) return ((uiBlock)%4 == 0); else return ((uiBlock)%16 == 0);
}

bool is_trailer_block(uint32_t uiBlock)
{
	// Test if we are in the small or big sectors
	if (uiBlock < 128) return ((uiBlock+1)%4 == 0); else return ((uiBlock+1)%16 == 0);
}

uint32_t get_trailer_block(uint32_t uiFirstBlock)
{
	// Test if we are in the small or big sectors
	if (uiFirstBlock<128) return uiFirstBlock+3; else return uiFirstBlock+15;
}

void press_to_continue() {
	string dummy = "";
	cout << "Press ENTER to continue... ";
	getline(cin, dummy);

}
void cls() {
#ifdef WIN32
	system("cls");
#endif
#ifndef WIN32
	system("clear");
#endif



}

void print_menu() {

	cout << "\nMain menu:\n";
	/* MC_AUTH_A         = 0x60,
	MC_AUTH_B         = 0x61,
	MC_READ           = 0x30,
	MC_WRITE          = 0xA0,
	MC_TRANSFER       = 0xB0,
	MC_DECREMENT      = 0xC0,
	MC_INCREMENT      = 0xC1,
	MC_STORE          = 0xC2, */

	cout << "h - display main menu\n";
	cout << "o - Open connection\n";
	cout << "at - analyse manually input trailer data\n";
	cout << "cls, clear - Clear screen\n";
	cout << "q - Exit\n";
	cout << "\n-- After connection is successfully opened, you may use following\n-- additional commands:\n";

	cout << "a - Authenticate with A key\n";
	cout << "b - Authenticate with B key\n";
	cout << "r - Read specific block data\n";
	cout << "w - Write specific block data\n";
	cout << "t - Transfer value block to volatile memory\n";
	cout << "d - Decrement value block\n";
	cout << "i - Increment value block\n";
	cout << "s - ReStore value block\n";
	cout << "c - Close existing connection\n";
	cout << "\n";


}

void close_connection() {

	cout << "Closing connection to " << pdi->acName << endl;
	nfc_disconnect(pdi);
	pdi = 0;
	connected = false;
	cout << "Connection closed." << endl;

}

bool open_connection() {
	pdi = nfc_connect(NULL);
	if (!pdi) {
		cout << "Could not connect to the device." << endl;
		return false;
	}
	nfc_initiator_init(pdi);

	nfc_configure(pdi,NDO_ACTIVATE_FIELD,false);


	nfc_configure(pdi,NDO_INFINITE_SELECT,false);
	nfc_configure(pdi,NDO_HANDLE_CRC,true);
	nfc_configure(pdi,NDO_HANDLE_PARITY,true);

	nfc_configure(pdi,NDO_ACTIVATE_FIELD,true); 
	cout << "Connected to " << pdi->acName << endl;
	if (!nfc_initiator_select_tag(pdi, NM_ISO14443A_106, NULL, 0, &ti)) {
		cout << "No MIFARE tag found!" << endl;
		press_to_continue();
		close_connection();
		return false;
	} 
	if ((ti.nai.btSak & 0x08) == 0) {
		cout << "This is not a valid MIFARE _classic_ tag!" << endl;
		press_to_continue();
		close_connection();
		return false;
	}
	b4k = (ti.nai.abtAtqa[1] == 0x02);
	cout << "Found MIFARE Classic " << (b4k ? 4 : 1) << "K tag, UID: " << bytearray_to_string(ti.nai.abtUid, 4) << endl;

	return true;
}

// b3de9843c86d
bool authenticate(byte* key, bool keyB, uint8_t sector) {
	uint8_t block = (sector+1)*4 - 1;
	memcpy(param.mpa.abtUid, ti.nai.abtUid,4);
	memcpy(param.mpa.abtKey, key, 6);

	bool res = nfc_initiator_mifare_cmd(pdi, (keyB ? MC_AUTH_B : MC_AUTH_A), block, &param);

	if (res)
		cout << "Authentication successful. :-P" << endl;
	else {
		cout << "Authentication FAILURE! :'( Tag halted, reconnecting..." << endl;
		close_connection();
		connected = open_connection();
	}

	return res;
}

void parse_trailer(byte* data) {
	byte keyA[6];
	byte keyB[6];
	byte AC[4];
	byte mask = 0x01;
	uint32_t ACint = 0;
	memcpy(keyA, data, 6);
	memcpy(AC, data+6, 4);
	memcpy(keyB, data+10, 6);
	memcpy(&ACint, data+6, 4);
	cout << "Key A: " << bytearray_to_string(keyA, 6) << endl;
	cout << "Key B: " << bytearray_to_string(keyB, 6) << endl << endl;
	cout << "Access Conditions: " << bytearray_to_string(AC, 4) << endl;
	cout << "AC matrix (x = bit set to 1; - = bit set to 0)\n" << endl;
	cout << "  C1 C2 C3 " << endl;
	AccessCondition acs[4];
	for (int i = 0; i <= 3; i++) 
		acs[i].c1 = ((AC[1] & (mask << (i+4))) > 0);
	for (int i = 0; i <= 3; i++) 
		acs[i].c2 = ((AC[2] & (mask << (i))) > 0);
	for (int i = 0; i <= 3; i++) 
		acs[i].c3 = ((AC[2] & (mask << (i+4))) > 0);

	for (int i=3; i >= 0; i--) {
		cout << "|" << (acs[i].c1 ? " x " : " - ") << (acs[i].c2 ? " x " : " - ") << (acs[i].c3 ? " x " : " - ") << "| block " << i << ((i == 3) ? " (trailer) " : "") << endl;
	}
	cout << endl;

		cout << "-- Trailer block has following AC set: " << endl;
	if ((!acs[3].c1) && (!acs[3].c2) && (!acs[3].c3))
		cout << "Key A may be written by itself, AC may be read by key A, key B may be read and written by key A." << endl;
	if ((!acs[3].c1) && (acs[3].c2) && (!acs[3].c3))
		cout << "Key A cannot be changed, AC may be read by key A, key B may be read by key A." << endl;
	if ((acs[3].c1) && (!acs[3].c2) && (!acs[3].c3))
		cout << "Key A may be changed by key B, AC may be read by both keys, key B may be changed by key B." << endl;
	if ((acs[3].c1) && (acs[3].c2) && (!acs[3].c3))
		cout << "AC may be read by both keys, nothing else on the trailer block allowed." << endl;
	if ((!acs[3].c1) && (!acs[3].c2) && (acs[3].c3))
		cout << "Transport configuration, everything on trailer block (except reading key A) may be done by key A." << endl;
	if ((!acs[3].c1) && (acs[3].c2) && (acs[3].c3))
		cout << "Key A may be changed by key B, AC may be read by both keys, changed by key B, key B may be changed by key B." << endl;
	if ((acs[3].c1) && (!acs[3].c2) && (acs[3].c3))
		cout << "AC may be read by both keys, written by key B. Nothing else on the trailer block allowed." << endl;
	if ((acs[3].c1) && (acs[3].c2) && (acs[3].c3))
		cout << "AC may be read by both keys, nothing else on the trailer block allowed." << endl;

	cout << endl;


	for (int i=2; i >= 0; i--) {
		cout << "-- Block " << i << " (relative to sector beginning) has following AC set: " << endl;

		if ((!acs[i].c1) && (!acs[i].c2) && (!acs[i].c3))
			cout << "Transport configuration; may be read, written, incremented and decremented by both keys." << endl;
		if ((!acs[i].c1) && (acs[i].c2) && (!acs[i].c3))
			cout << "May be read by both keys, read-only." << endl;
		if ((acs[i].c1) && (!acs[i].c2) && (!acs[i].c3))
			cout << "May be read by both keys, written by key B. Value operations not allowed." << endl;
		if ((acs[i].c1) && (acs[i].c2) && (!acs[i].c3))
			cout << "May be read and decremented by both keys, written and incremented only by key B" << endl;
		if ((!acs[i].c1) && (!acs[i].c2) && (acs[i].c3))
			cout << "Decrement-only block. May be read and decremented by both keys. Nothing else allowed." << endl;
		if ((!acs[i].c1) && (acs[i].c2) && (acs[i].c3))
			cout << "May be accessed (read/write) only by key B. Value operations not allowed." << endl;
		if ((acs[i].c1) && (!acs[i].c2) && (acs[i].c3))
			cout << "May be read only by key B, read-only." << endl;
		if ((acs[i].c1) && (acs[i].c2) && (acs[i].c3))
			cout << "Dead block, no operation is allowed." << endl;


		cout << endl;
	}


}

bool readblock(uint8_t block) {
	bool res = nfc_initiator_mifare_cmd(pdi, MC_READ, block, &param);

	if (res) {
		cout << bytearray_to_string(param.mpd.abtData, 16) << "\n( " << bytearray_to_string(param.mpd.abtData, 16, false) << " ) " << endl;
		if (is_trailer_block(block)) {
			cout << "\nThis is the TRAILER block!" << endl;
			parse_trailer(param.mpd.abtData);
		}
	} else {
		cout << "Could not read the data block! Tag halted, reconnecting..." << endl;
		close_connection();
		connected = open_connection();
	}
	return res;

}

bool writeblock(uint8_t block, byte* data) {
	if (is_trailer_block(block)) {
		string response = "";
		cout << "----- !!!!! WARNING !!!!! -----" << endl;
		cout << "-- You are trying to write data into a trailer block of certain sector." << endl;
		cout << "-- Writing incorrect data may damage your MIFARE card." << endl;
		cout << "Proceed only if you are completely sure what you are doing." << endl;
		cout << "Continue?? (y - yes, anything else - no) : " << endl;
		getline(cin, response);
		if (response.compare("y") != 0) {
			cout << "Aborting." << endl;
			return false;
		}

	}

	memcpy(param.mpd.abtData, data, 16);
	bool res = nfc_initiator_mifare_cmd(pdi, MC_WRITE, block, &param);

	if (res) {
		cout << "Successfully wrote " << bytearray_to_string(param.mpd.abtData, 16) << "into block " << (UINT) block << endl;
	} else {
		cout << "Could not write the data block! Tag halted, reconnecting..." << endl;
		close_connection();
		connected = open_connection();
	}
	return res;

}

bool valueblock(const mifare_cmd cmd, uint8_t block, byte* data) {
	memcpy(param.mpv.abtValue, data, 4);
	bool res = nfc_initiator_mifare_cmd(pdi, cmd, block, &param);
	if (res) {
		cout << "Command successfully completed." << endl;
		if ((cmd == MC_INCREMENT) || (cmd == MC_DECREMENT))
			cout << "Don't forget to TRANSFER(t) the data back to permanent memory of the chip" << endl;
	} else {
		cout << "Something failed. Command was NOT completed. Tag halted, reconnecting..." << endl;
		close_connection();
		connected = open_connection();
	}
	return res;

}



int main(int argc, char* argv[])
{
	//set_console_size();

	string menu_option;
	connected = false;	

	cout << "\n*** MiCmd " << VERSION << " -- MIFARE(R) command line ***\n";
	print_menu();
	while (true) {

		cout << '\n';
		if (connected) {
			cout << "You are CONNECTED to " << pdi->acName << endl;
			cout << "Found MIFARE Classic " << (b4k ? 4 : 1) << "K tag, UID: " << bytearray_to_string(ti.nai.abtUid, 4) << endl;
		}
		else
			cout << "You are NOT connected, additional commands will not work.\n";
		cout << "Type h for help.\n";
		cout << "MiCmd " << VERSION << "> " ;
		getline(cin, menu_option);
		cout << endl;
		if ((menu_option.compare("q")) == 0) {
			if (connected)
				close_connection();

			return 0;
		}

		if ((menu_option.compare("h")) == 0) {
			print_menu();
			continue;
		}

		if ((menu_option.compare("o")) == 0) {
			if (connected) {
				cout << "You are already connected, disconnect with c first!" << endl;
				continue;
			}
			connected = open_connection();
			continue;
		}
		if (((menu_option.compare("cls")) == 0) || (menu_option.compare("clear") == 0)) {
			cls();
			continue;
		}

		if (menu_option.compare("at") == 0) {
			string data = "";
			int length = 0;
			cout << "Enter trailer block data (16B HEX value, without spaces): ";
			getline(cin, data);
			cout << endl;
			cout << "-- !!!! ATTENTION !!!!\nManual parsing does NOT detect inner format violation of AC part of the trailer block." << endl;
			cout << "-- It only computes AC bits from 4-byte value by applying bitwise operations." << endl;
			cout << "-- It totally ignores inverse AC bits in those 4 bytes." << endl;
			cout << "-- DO NOT rely on this when calculating correct 4-byte value to write into the trailer block!" << endl;
			cout << "-- !!!! ATTENTION !!!!" << endl << endl;

			parse_trailer(string_to_bytearray(data, &length));

			continue;
		}
		if (connected) {
			if ((menu_option.compare("c")) == 0) {
				close_connection();
				continue;
			}
			if (((menu_option.compare("a")) == 0) || ((menu_option.compare("b")) == 0)) {
				byte* key_c;
				int bbbb;
				char tmp[20];

				uint8_t block = 0;
				cout << "Enter sector number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				cout << "Enter key (6B HEX value, WITHOUT spaces): ";
				string key = "";
				getline(cin, key);


				key_c = string_to_bytearray(key, &bbbb);
				authenticate(key_c, (menu_option.compare("b") == 0), block);

				continue;
			}
			if ((menu_option.compare("r")) == 0) {
				char tmp[20];
				uint8_t block;
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin); 
				sscanf(tmp, "%d", &block);
				readblock(block);
				continue;
			}

			if ((menu_option.compare("w")) == 0) {
				int length = 0;
				char tmp[20];
				uint8_t block;
				string data = "";
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				
				cout << "Enter data (16B hex, WITHOUT spaces) to write: ";
				getline(cin, data);


				writeblock(block, string_to_bytearray(data, &length));

				continue;
			}

			if ((menu_option.compare("s")) == 0) {
				char tmp[20];
				string data = "";
				int length = 0;
				uint8_t block;
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				cout << "Enter data (enter 4B HEX value, WITHOUT spaces): ";
				getline(cin, data);
				valueblock(MC_STORE, block, string_to_bytearray(data, &length));

				continue;
			}

			if ((menu_option.compare("i")) == 0) {
				char tmp[20];
				byte* data = new byte[4];
				string how_many = "";
				int length = 0;
				uint8_t block;
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				cout << "Increment by what number (enter 4B HEX value, WITHOUT spaces)? ";
				getline(cin, how_many);
				valueblock(MC_INCREMENT, block, string_to_bytearray(how_many, &length));

				continue;
			}

			if ((menu_option.compare("d")) == 0) {
				char tmp[20];
				byte* data = new byte[4];
				string how_many = "";
				int length = 0;
				uint8_t block;
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				cout << "Decrement by what number (enter 4B HEX value, WITHOUT spaces)? ";
				getline(cin, how_many);
				valueblock(MC_DECREMENT, block, string_to_bytearray(how_many, &length));

				continue;
			}

			if ((menu_option.compare("t")) == 0) {
				char tmp[20];
				string data = "";
				int length = 0;
				uint8_t block;
				cout << "Enter block number: ";
				fgets(tmp, 20, stdin);
				sscanf(tmp, "%d", &block);
				cout << "Enter data (4B HEX value, WITHOUT spaces): ";
				getline(cin, data);
				valueblock(MC_TRANSFER, block, string_to_bytearray(data, &length));

				continue;
			}
		}
		cout << "Command " << menu_option << " not understood.\nRemember, to use additional commands like Read,Write,...\nyou have to be connected to the reader first." << endl;
		press_to_continue();
	}




}

