#ifndef _SUPERMAN_QUEUE_H
#define _SUPERMAN_QUEUE_H

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include "packet_info.h"

#define SUPERMAN_QUEUE_DROP 1
#define SUPERMAN_QUEUE_SEND 2

int FindQueuedPacket(struct net *net, uint32_t ifindex, uint32_t daddr);
int EnqueuePacket(struct superman_packet_info* spi, uint32_t addr, unsigned int (*callback_after_queue)(struct superman_packet_info*, bool));
int SetVerdict(int verdict, struct net *net, uint32_t ifindex, uint32_t daddr);
void FlushQueue(void);

//bool EnqueueSKRequest(uint32_t originaddr, uint32_t targetaddr);

bool InitQueue(void);
void DeInitQueue(void);

int queue_info_proc_show(struct seq_file *m, void *v);

#endif

#endif
