#include "superman.h"
#include "processor.h"
#include "netlink.h"
#include "security_table.h"

#ifdef __KERNEL__

#include "interfaces_table.h"
#include "packet.h"
#include "security.h"
#include "queue.h"

void LoadNodeCertificateAndSecureInterface(uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_dh_privatekey_filename_len, unsigned char* node_dh_privatekey_filename, uint32_t interface_name_len, unsigned char* interface_name)
{
	struct net *net = get_net_ns_by_pid(task_pid_nr(current));
	struct net_device* dev;
	uint32_t ifindex;
	dev = dev_get_by_name(net, interface_name);
	if(dev == NULL) return;
	ifindex = dev->ifindex;
	dev_put(dev);

	LoadNodeCertificateThenSecureInterface(GetNSIDFromNet(net), ifindex, node_cert_filename_len, node_cert_filename, node_dh_privatekey_filename_len, node_dh_privatekey_filename);
}

void SecureInterface(uint32_t netns_id, uint32_t ifindex)
{
	struct net *net = GetNetFromNSID(netns_id);
	if(net != NULL)
	{
		printk(KERN_INFO "SUPERMAN: Adding to the interfaces table.\n");
		AddInterfacesTableEntry(net, ifindex);
		return;
	}
}

void SecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	if(interface_name_len > 0)
	{
		printk(KERN_INFO "SUPERMAN: Adding %s to the interfaces table.\n", interface_name);
		AddInterfacesTableEntryByName(interface_name);
		return;
	}
}

void UnsecureInterface(uint32_t netns_id, uint32_t ifindex)
{
	struct net *net = GetNetFromNSID(netns_id);
	if(net != NULL)
	{
		printk(KERN_INFO "SUPERMAN: Removing from the interfaces table.\n");
		RemoveInterfacesTableEntry(net, ifindex);
	}
}

void UnsecureInterfaceByName(uint32_t interface_name_len, unsigned char* interface_name)
{
	printk(KERN_INFO "SUPERMAN: Removing %s from the interfaces table.\n", interface_name);
	RemoveInterfacesTableEntryByName(interface_name);
}

// void UpdateSupermanInterfaceTableEntry(uint32_t interface_name_len, unsigned char* interface_name, bool monitor_flag)
// {
// 	if(monitor_flag)
// 	{
// 		printk(KERN_INFO "SUPERMAN: Adding %s to the interfaces table.\n", interface_name);
// 		AddInterfacesTableEntryByName(interface_name);
// 	}
// 	else
// 	{
// 		printk(KERN_INFO "SUPERMAN: Removing %s from the interfaces table.\n", interface_name);
// 		RemoveInterfacesTableEntryByName(interface_name);
// 	}
// }

void UnloadAll()
{
	FlushInterfacesTable();
	FlushQueue();
	FlushSecurityTable();
}

void UpdateSupermanSecurityTableEntry(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	struct net* net = GetNetFromNSID(netns_id);
	UpdateOrAddSecurityTableEntry(net, ifindex, address, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);

	// Any packets waiting in the queue to be sent can go now.
	if(flag == SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
		SetVerdict(SUPERMAN_QUEUE_SEND, net, ifindex, address);
}

void UpdateSupermanBroadcastKey(uint32_t netns_id, uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	struct net* net = GetNetFromNSID(netns_id);
	UpdateBroadcastKey(net, ifindex, sk_len, sk, ske_len, ske, skp_len, skp, overwrite);
}

void TriggerSupermanDiscoveryRequest(void)
{
	struct net *net;
	struct net_device *dev;

	for_each_net(net) {
		INTERFACE_ITERATOR_START(net, dev)
		RaiseSupermanDiscoveryRequest(GetNSIDFromNet(net), dev->ifindex);
		INTERFACE_ITERATOR_END
	}
}

void SendSupermanDiscoveryRequest(uint32_t netns_id, uint32_t ifindex, uint32_t sk_len, unsigned char* sk)
{
	struct net* net = GetNetFromNSID(netns_id);
	SendDiscoveryRequestPacket(net, ifindex, sk_len, sk);
}

void SendSupermanCertificateRequest(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk)
{
	struct net* net = GetNetFromNSID(netns_id);
	SendCertificateRequestPacket(net, ifindex, address, sk_len, sk);
}

void SendSupermanCertificateExchange(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	struct net* net = GetNetFromNSID(netns_id);
	SendCertificateExchangePacket(net, ifindex, address, certificate_len, certificate);
}

void SendSupermanCertificateExchangeWithBroadcastKey(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t certificate_len, unsigned char* certificate)
{
	struct net* net = GetNetFromNSID(netns_id);
	uint32_t bkey_len;
	unsigned char* bkey;

	// Get a reference to the actual key, no need for a copy.
	if(GetBroadcastKey(net, ifindex, &bkey_len, &bkey))
	{
		SendCertificateExchangeWithBroadcastKeyPacket(net, ifindex, address, certificate_len, certificate, bkey_len, bkey);
	}
}

void SendSupermanBroadcastKeyExchange(uint32_t netns_id, uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key, bool only_if_changed)
{
	struct net* net = GetNetFromNSID(netns_id);
	struct security_table_entry* entry;
	bool send = true;

	// We can only do this if we already have a broadcast key
	if(GetSecurityTableEntry(net, ifindex, INADDR_BROADCAST, &entry) && entry->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED)
	{
		if(only_if_changed)
		{
			if(entry->sk_len == broadcast_key_len && memcmp(entry->sk, broadcast_key, broadcast_key_len) == 0)
				send = false;
		}

		if(send)
			SendBroadcastKeyExchange(net, ifindex, broadcast_key_len, broadcast_key);
	}
}

void SendSupermanSKInvalidate(uint32_t netns_id, uint32_t ifindex, uint32_t address)
{
	struct net* net = GetNetFromNSID(netns_id);
	SendSKInvalidatePacket(net, ifindex, address);
}

#else

#include "security.h"

void LoadNodeCertificateThenSecureInterface(uint32_t netns_id, uint32_t ifindex, uint32_t node_cert_filename_len, unsigned char* node_cert_filename, uint32_t node_dh_privatekey_filename_len, unsigned char* node_dh_privatekey_filename)
{
	// Try and load the certificate. If it loads, we request to secure the interface.
	if(LoadNodeCertificates(netns_id, ifindex, node_cert_filename, node_dh_privatekey_filename))
	{
		// Request to secure the interface
		SecureInterface(netns_id, ifindex);
	}
}

void RaiseSupermanDiscoveryRequest(uint32_t netns_id, uint32_t ifindex)
{
	uint32_t sk_len;
	unsigned char* sk;
	if(MallocAndCopyPublickey(netns_id, ifindex, &sk_len, &sk))
	{
		//lprintf("Main: Calling SendSupermanDiscoveryRequest...\n");
		SendSupermanDiscoveryRequest(netns_id, ifindex, sk_len, sk);

		free(sk);
	}
}

void RaiseNewBroadcastKey(uint32_t netns_id, uint32_t ifindex)
{
	// In userspace, we don't know if the kernel has a broadcast key.
	uint32_t bk_len;
	unsigned char* bk;
	// lprintf("Security: \tGenerating a new broadcast key (just in case the kernel doesn't have one yet)...\n");
	if(MallocAndGenerateNewKey(&bk_len, &bk))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		// lprintf("Security: \tGenerating SKE and SKP for the new broadcast key (again, just in case)...\n");
		if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
		{
			// lprintf("Security: \tUpdating the new broadcast key (again, just in case)...\n");
			UpdateSupermanBroadcastKey(netns_id, ifindex, bk_len, bk, ske_len, ske, skp_len, skp, false);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;
		}
		else
			lprintf("Security: \tFailed to generate SKE and SKP from the new broadcast key.\n");
		free(bk);
		bk = NULL;
	}
}

void ReceivedSupermanDiscoveryRequest(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndDHAndGenerateSharedkeys(netns_id, ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		// lprintf("Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);

		uint32_t our_sk_len;
		unsigned char* our_sk;
		// lprintf("Processor: \tGrabbing our SK...\n");
		if(MallocAndCopyPublickey(netns_id, ifindex, &our_sk_len, &our_sk))
		{
			// lprintf("Processor: \tRequesting to send a certificate request...\n");
			SendSupermanCertificateRequest(netns_id, ifindex, address, our_sk_len, our_sk);
			free(our_sk);
		}
		else
			lprintf("Processor: \tFailed to obtain our SK.\n");

		free(ske);
		free(skp);
	}
	else
		lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateRequest(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;

	// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
	if(MallocAndDHAndGenerateSharedkeys(netns_id, ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		// lprintf("Processor: \tRequesting a security table update...\n");
		UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);
		free(ske);
		free(skp);

		uint32_t our_cert_len;
		unsigned char* our_cert;
		// lprintf("Processor: \tGrabbing our certificate...\n");
		if(MallocAndCopyCertificate(netns_id, ifindex, &our_cert_len, &our_cert))
		{
			// lprintf("Processor: \tRequesting to send a certificate exchange...\n");
			SendSupermanCertificateExchange(netns_id, ifindex, address, our_cert_len, our_cert);
			free(our_cert);
		}
		else
			lprintf("Processor: \tFailed to obtain our certificate.\n");
	}
	else
		lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
}

void ReceivedSupermanCertificateExchange(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate)
{
	// lprintf("Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(netns_id, ifindex, certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;
		// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndDHAndGenerateSharedkeys(netns_id, ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			// lprintf("Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1);
			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			uint32_t our_cert_len;;
			unsigned char* our_cert;
			// lprintf("Processor: \tGrabbing our certificate...\n");
			if(MallocAndCopyCertificate(netns_id, ifindex, &our_cert_len, &our_cert))
			{

				/*
				// In userspace, we don't know if the kernel has a broadcast key.

				uint32_t bk_len;
				unsigned char* bk;

				lprintf("Processor: \tGenerating a new broadcast key (just in case the kernel doesn't have one yet)...\n");
				if(MallocAndGenerateNewKey(&bk_len, &bk))
				{
					lprintf("Processor: \tGenerating SKE and SKP for the new broadcast key (again, just in case)...\n");
					if(MallocAndGenerateSharedkeys(bk_len, bk, &ske_len, &ske, &skp_len, &skp))
					{
						lprintf("Processor: \tUpdating the new broadcast key (again, just in case)...\n");
						UpdateSupermanBroadcastKey(bk_len, bk, ske_len, ske, skp_len, skp, false);
						free(ske);
						ske = NULL;
						free(skp);
						skp = NULL;
					}
					else
						lprintf("Processor: \tFailed to generate SKE and SKP from the new broadcast key.\n");

					free(bk);
					bk = NULL;
				}
				else
					lprintf("Processor: \tFailed to generate a new broadcast key.\n");
				*/

				// Send the certificate exchange with the broadcast key. The broadcast key is in kernel memory.
				// lprintf("Processor: \tRequesting to send a certificate exchange with broadcast key...\n");
				SendSupermanCertificateExchangeWithBroadcastKey(netns_id, ifindex, address, our_cert_len, our_cert);

				free(our_cert);
			}
			else
				lprintf("Processor: \tFailed to obtain our certificate..\n");
		}
		else
		{
			lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
		}
	}
	else
	{
		lprintf("Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
	}
}

void ReceivedSupermanCertificateExchangeWithBroadcastKey(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, uint32_t certificate_len, unsigned char* certificate, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	// lprintf("Processor: \tVerifying certificate...\n");
	if(VerifyCertificate(netns_id, ifindex, certificate_len, certificate, sk, sk_len))
	{
		uint32_t ske_len;
		unsigned char* ske;
		uint32_t skp_len;
		unsigned char* skp;

		// lprintf("Processor: \tObtaining SKE and SKP from the SK...\n");
		if(MallocAndDHAndGenerateSharedkeys(netns_id, ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
		{
			// lprintf("Processor: \tRequesting a security table update...\n");
			UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, -1);

			free(ske);
			ske = NULL;
			free(skp);
			skp = NULL;

			// lprintf("Processor: \tGenerating SKE and SKP for the broadcast key...\n");
			if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
			{
				// This has to be done before we commit the new key.
				// lprintf("Processor: \tRequesting a broadcast key update for nodes we're associated with...\n");

				SendSupermanBroadcastKeyExchange(netns_id, ifindex, broadcast_key_len, broadcast_key, true);

				UpdateSupermanBroadcastKey(netns_id, ifindex, broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);

				free(ske);
				ske = NULL;
				free(skp);
				skp = NULL;
			}
			else
				lprintf("Processor: \tFailed to generate SKE and SKP from the broadcast key.\n");
		}
		else
		{
			lprintf("Processor: \tFailed to generate SKE and SKP from the given SK.\n");
			UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
		}
	}
	else
	{
		lprintf("Processor: \tCertificate validation failed. Requesting a security table update.\n");
		UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
	}
}

void ReceivedSupermanAuthenticatedSKResponse(uint32_t netns_id, uint32_t ifindex, uint32_t address, uint32_t sk_len, unsigned char* sk, int32_t timestamp)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndDHAndGenerateSharedkeys(netns_id, ifindex, sk_len, sk, &ske_len, &ske, &skp_len, &skp))
	{
		//lprintf("Processor: SK Response - Keys for %u.%u.%u.%u:\n", 0x0ff & address, 0x0ff & (address >> 8), 0x0ff & (address >> 16), 0x0ff & (address >> 24));
		//DumpKeys(sk_len, sk, ske_len, ske, skp_len, skp);

		UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);
		free(ske);
		free(skp);
	}
}

void ReceivedSupermanSKInvalidate(uint32_t netns_id, uint32_t ifindex, uint32_t address)
{
	UpdateSupermanSecurityTableEntry(netns_id, ifindex, address, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, "", 0, "", 0, "", -1);
}

void ReceivedSupermanBroadcastKeyExchange(uint32_t netns_id, uint32_t ifindex, uint32_t broadcast_key_len, unsigned char* broadcast_key)
{
	uint32_t ske_len;
	unsigned char* ske;
	uint32_t skp_len;
	unsigned char* skp;
	if(MallocAndGenerateSharedkeys(broadcast_key_len, broadcast_key, &ske_len, &ske, &skp_len, &skp))
	{
		UpdateSupermanBroadcastKey(netns_id, ifindex, broadcast_key_len, broadcast_key, ske_len, ske, skp_len, skp, true);
		free(ske);
		ske = NULL;
		free(skp);
		skp = NULL;
	}
}

#endif
