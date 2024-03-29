#ifndef __SUPERMAN_SECURITY_H
#define __SUPERMAN_SECURITY_H

#include "superman.h"

// #define AEAD_ALG_NAME "authenc(hmac(sha256),cbc(aes))"
#define AEAD_ALG_NAME "gcm(aes)"
#define HMAC_ALG_NAME "hmac(sha256)"
#define SYM_KEY_LEN 32
#define MAC_LEN 4
#define HMAC_LEN 4

#ifdef __KERNEL__

#include "packet_info.h"

void dump_packet(struct sk_buff* skb);
void dump_bytes(void* d, int len);

// TODO: Add sanity checks to ensure skb size against superman header reported payload lengths.
unsigned int AddE2ESecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool));
unsigned int RemoveE2ESecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool));
unsigned int AddP2PSecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool));
unsigned int RemoveP2PSecurity(struct superman_packet_info* spi, unsigned int (*callback)(struct superman_packet_info*, bool));

bool InitSecurity(void);
void DeInitSecurity(void);

#else

void DumpKeys(uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp);

bool MallocAndCopyPublickey(uint32_t netns_id, uint32_t ifindex, uint32_t* sk_len, unsigned char** sk);
bool MallocAndCopyCertificate(uint32_t netns_id, uint32_t ifindex, uint32_t* certificate_len, unsigned char** certificate);
bool MallocAndGenerateSharedkeys(uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp);
bool MallocAndDHAndGenerateSharedkeys(uint32_t netns_id, uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t* ske_len, unsigned char** ske, uint32_t* skp_len, unsigned char** skp);
bool MallocAndGenerateNewKey(uint32_t* key_len, unsigned char** key);

bool LoadNodeCertificates(uint32_t netns_id, uint32_t ifindex, unsigned char* node_cert_filename, unsigned char* node_dh_privatekey_filename);
bool VerifyCertificate(uint32_t netns_id, uint32_t ifindex, uint32_t cert_data_len, unsigned char* cert_data, unsigned char* node_share, int node_share_len);
bool TestCertificate(unsigned char* cert_filename);
bool InitSecurity(unsigned char* ca_cert_filename);
void DeInitSecurity(void);

#endif

#endif
