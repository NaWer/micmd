/*
 
Public platform independent Near Field Communication (NFC) library
Copyright (C) 2009, Roel Verdult
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

*/

#ifndef _LIBNFC_TYPES_H_
#define _LIBNFC_TYPES_H_

#include <stdint.h>
#include <stdbool.h>

#include "defines.h"

typedef uint8_t byte_t;

// Compiler directive, set struct alignment to 1 byte_t for compatibility
#pragma pack(1)

typedef enum {
  CT_PN531                    = 0x10,
  CT_PN532                    = 0x20,
  CT_PN533                    = 0x30,
} chip_type;

struct dev_callbacks;                // Prototype the callback struct

typedef struct {
  const struct dev_callbacks* pdc;   // Callback functions for handling device specific wrapping
  char acName[DEVICE_NAME_LENGTH];   // Device name string, including device wrapper firmware
  chip_type ct;                      // PN53X chip type, this is useful for some "bug" work-arounds
  dev_spec ds;                       // Pointer to the device connection specification
  bool bActive;                      // This represents if the PN53X device was initialized succesful
  bool bCrc;                         // Is the crc automaticly added, checked and removed from the frames
  bool bPar;                         // Does the PN53x chip handles parity bits, all parities are handled as data
  uint8_t ui8TxBits;                     // The last tx bits setting, we need to reset this if it does not apply anymore
} dev_info;

struct dev_callbacks {
  const char* acDriver;              // Driver description
  dev_info* (*connect)(const uint32_t uiIndex);
  bool (*transceive)(const dev_spec ds, const byte_t* pbtTx, const uint32_t uiTxLen, byte_t* pbtRx, uint32_t* puiRxLen);
  void (*disconnect)(dev_info* pdi);
};

typedef enum {
  DCO_HANDLE_CRC              = 0x00,
  DCO_HANDLE_PARITY           = 0x01,
  DCO_ACTIVATE_FIELD          = 0x10,
  DCO_ACTIVATE_CRYPTO1        = 0x11,
  DCO_INFINITE_SELECT         = 0x20,
  DCO_ACCEPT_INVALID_FRAMES   = 0x30,
  DCO_ACCEPT_MULTIPLE_FRAMES  = 0x31
}dev_config_option;

////////////////////////////////////////////////////////////////////
// nfc_reader_list_passive - using InListPassiveTarget 

typedef enum {
  IM_ISO14443A_106  = 0x00,
  IM_FELICA_212     = 0x01,
  IM_FELICA_424     = 0x02,
  IM_ISO14443B_106  = 0x03,
  IM_JEWEL_106      = 0x04
}init_modulation;

typedef struct {
  byte_t abtAtqa[2];
  byte_t btSak;
  uint32_t uiUidLen;
  byte_t abtUid[10];
  uint32_t uiAtsLen;
  byte_t abtAts[36];
}tag_info_iso14443a;

typedef struct {
  uint32_t uiLen;
  byte_t btResCode;
  byte_t abtId[8];
  byte_t abtPad[8];
  byte_t abtSysCode[2];
}tag_info_felica;

typedef struct {
  byte_t abtAtqb[12];
  byte_t abtId[4];
  byte_t btParam1;
  byte_t btParam2;
  byte_t btParam3;
  byte_t btParam4;
  byte_t btCid;
  uint32_t uiInfLen;
  byte_t abtInf[64];
}tag_info_iso14443b;

typedef struct {
  byte_t btSensRes[2];
  byte_t btId[4];
}tag_info_jewel;

typedef union {
  tag_info_iso14443a tia;
  tag_info_felica tif;
  tag_info_iso14443b tib;
  tag_info_jewel tij;
}tag_info;

////////////////////////////////////////////////////////////////////
// InDataExchange, MIFARE Classic card 

typedef enum {
  MC_AUTH_A         = 0x60,
  MC_AUTH_B         = 0x61,
  MC_READ           = 0x30,
  MC_WRITE          = 0xA0,
  MC_TRANSFER       = 0xB0,
  MC_DECREMENT      = 0xC0,
  MC_INCREMENT      = 0xC1,
  MC_STORE          = 0xC2,
}mifare_cmd;

// MIFARE Classic command params
typedef struct {
  byte_t abtKey[6];
  byte_t abtUid[4];
}mifare_param_auth;

typedef struct {
  byte_t abtData[16];
}mifare_param_data;

typedef struct {
  byte_t abtValue[4];
}mifare_param_value;

typedef union {
  mifare_param_auth mpa;
  mifare_param_data mpd;
  mifare_param_value mpv;
}mifare_param;

// Reset struct alignment to default
#pragma pack()

#endif // _LIBNFC_TYPES_H_
