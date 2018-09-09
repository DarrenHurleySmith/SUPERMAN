#ifndef _SUPERMAN_INTERFACES_TABLE_H
#define _SUPERMAN_INTERFACES_TABLE_H

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/spinlock.h>

struct interfaces_table_entry {
	struct list_head	l;
	struct net 			*net;
	int32_t				ifindex;
};

rwlock_t* GetInterfacesTableLock(void);
struct list_head* GetInterfacesTable(void);
uint32_t GetInterfacesCount(void);

#define INTERFACE_ITERATOR_START(NET_VAR, DEV_VAR)											\
	{															\
		int i = 0;													\
		int32_t* interfaces = NULL;									\
		struct net **nets = NULL;										\
		uint32_t interfaces_count = 0;											\
		rwlock_t* interfaces_table_lock = GetInterfacesTableLock();							\
		read_lock_bh(interfaces_table_lock);										\
		{														\
			interfaces_count = GetInterfacesCount();								\
			if(interfaces_count > 0)										\
			{													\
				struct list_head* interfaces_table = GetInterfacesTable();					\
				interfaces = kmalloc(interfaces_count * sizeof(int32_t), GFP_ATOMIC);				\
				nets = kmalloc(interfaces_count * sizeof(struct net*), GFP_ATOMIC);				\
				if(interfaces != NULL)										\
				{												\
					struct list_head *pos;									\
					list_for_each(pos, interfaces_table) {							\
						interfaces[i++] = ((struct interfaces_table_entry *)pos)->ifindex;		\
						nets[i++] = ((struct interfaces_table_entry *)pos)->net;				\
					}											\
				}												\
				else												\
					interfaces_count = 0;									\
			}													\
		}														\
		read_unlock_bh(interfaces_table_lock);										\
		for(i = 0; i < interfaces_count; i++)										\
		{														\
			uint32_t ifindex = interfaces[i];									\
			NET_VAR = nets[i];															\
			DEV_VAR = dev_get_by_index(NET_VAR, ifindex);								\
			if(DEV_VAR == NULL)											\
			{													\
				printk(KERN_INFO "SUPERMAN: Interfaces Iterator - \t\tNo device for interface %i.\n", ifindex);	\
				continue;											\
			}													\
			else												\
			{

#define INTERFACE_ITERATOR_END													\
			}													\
			dev_put(dev);												\
		}														\
		kfree(interfaces);												\
	}


bool InitInterfacesTable(void);
void DeInitInterfacesTable(void);
void FlushInterfacesTable(void);

bool HasInterfacesTableEntry(struct net *net, uint32_t ifindex);
bool AddInterfacesTableEntry(struct net *net, uint32_t ifindex);
bool AddInterfacesTableEntryByName(char* ifname);
bool RemoveInterfacesTableEntry(struct net *net, uint32_t ifindex);
bool RemoveInterfacesTableEntryByName(char* ifname);

int interfaces_table_info_proc_show(struct seq_file *m, void *v);

#endif

#endif
