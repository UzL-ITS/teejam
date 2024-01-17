#include "encl_t.h"
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/aes.h>

uint8_t plain[16] = { 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00 };


uint8_t cipher[16];

void wssl_update_plain_text() {
  static uint64_t plain_cnt = 1;
  
  plain[0] = plain_cnt % 256;
  plain[1] = (plain_cnt / 256) % 256;
  plain[2] = ((plain_cnt / 256) / 256) % 256;
  plain[3] = (((plain_cnt / 256) / 256) / 256) % 256;
  plain[4] = ((((plain_cnt / 256) / 256) / 256) / 256) % 256;
  plain[5] = (((((plain_cnt / 256) / 256) / 256) / 256) / 256) % 256;
  plain[6] = ((((((plain_cnt / 256) / 256) / 256) / 256) / 256) / 256) % 256;
  plain[7] = (((((((plain_cnt / 256) / 256) / 256) / 256) / 256) / 256) / 256) % 256;

  plain_cnt++;
}

// Plain texts are obtained from debugging purposes only and are of course not required for key reconstruction
void wssl_get_plain(uint8_t *pbuffer) {
  for (int i = 0; i < 16; i++) {
    pbuffer[i] = plain[i];
  }
}

void wssl_get_cipher(uint8_t *cbuffer) {
  for (int i = 0; i < 16; i++) {
    cbuffer[i] = cipher[i];
  }
}

void wssl_aes_enc() {

  uint8_t key[16] =   { 0xf3, 0xb7, 0xa3, 0x78, 
                        0xe1, 0x4d, 0x1c, 0x2f, 
                        0x5e, 0x55, 0x62, 0x35,
                        0xf1, 0xe7, 0xcc, 0x32 }; 

  uint8_t iv[16] =    { 0x00, 0x01, 0x02, 0x03, 
                        0x04, 0x05, 0x06, 0x07, 
                        0x08, 0x09, 0x0a, 0x0b, 
                        0x0c, 0x0d, 0x0e, 0x0f };

  
  Aes aes;
  wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
  wc_AesCbcEncrypt(&aes, cipher, plain, sizeof(plain));  
}

void* get_wssl_aes_enc_address() {
  return wssl_aes_enc;
}
