#ifdef __KERNEL__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>

#include "security_table.h"
#include "security.h"

#define SECURITY_TABLE_MAX_LEN 1024

static unsigned int security_table_len;
static rwlock_t security_table_lock = __RW_LOCK_UNLOCKED(security_table_lock);
static LIST_HEAD(security_table_head);

#define list_is_first(e) (&e->l == security_table_head.next)

uint16_t GetNextTimestampFromSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t addr)
{
	struct security_table_entry* entry;
	if(GetSecurityTableEntry(net, ifindex, addr, &entry))
	{
		if(entry->timestamp == 0xFFFF) entry->timestamp = 0;
		entry->timestamp++;
		return entry->timestamp;
	}
	return 0;
}

static inline void __security_table_flush(void)
{
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;
		list_del(&e->l);
		security_table_len--;
		kfree(e->sk);
		kfree(e->ske);
		kfree(e->skp);
		kfree(e);
	}
}

static inline bool __security_table_add(struct security_table_entry *e)
{
	if (security_table_len >= SECURITY_TABLE_MAX_LEN) {
		printk(KERN_WARNING "SUPERMAN: security_table - \tMax list len reached (%d items).\n", SECURITY_TABLE_MAX_LEN);
		return false;
	}

	if (list_empty(&security_table_head)) {
		list_add(&e->l, &security_table_head);
	}
	else
	{
		list_add_tail(&e->l, &security_table_head);
	}
	return true;
}

static inline struct security_table_entry *__security_table_find(struct net *net, uint32_t ifindex, uint32_t daddr)
{
	struct list_head *pos;

	list_for_each(pos, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;

		if (e->net == net && e->ifindex == ifindex && e->daddr == daddr)
			return e;
	}
	return NULL;
}

static inline bool __security_table_del(struct security_table_entry *e)
{
	if (e == NULL)
		return false;

	list_del(&e->l);

	security_table_len--;

	return true;
}

bool RemoveSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t daddr)
{
	struct security_table_entry *e;

	write_lock_bh(&security_table_lock);

	if ((e = __security_table_find(net, ifindex, daddr)) && __security_table_del(e))
	{
		if(e->sk)
			kfree(e->sk);
		if(e->ske)
			kfree(e->ske);
		if(e->skp)
			kfree(e->skp);
		e->sk = NULL;
		e->ske = NULL;
		e->skp = NULL;
		kfree(e);
		write_unlock_bh(&security_table_lock);
		return true;
	}

	write_unlock_bh(&security_table_lock);
	return false;
}

bool HasSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t daddr)
{
	struct security_table_entry* entry;
	read_lock_bh(&security_table_lock);
	entry = __security_table_find(net, ifindex, daddr);
	read_unlock_bh(&security_table_lock);
	return entry != NULL;
}

bool GetSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t daddr, struct security_table_entry** entry)
{
	if(!entry) return false;

	//printk(KERN_INFO "SUPERMAN: Security_Table - GetSecurityTableEntry - %u.%u.%u.%u\n", 0x0ff & daddr, 0x0ff & (daddr >> 8), 0x0ff & (daddr >> 16), 0x0ff & (daddr >> 24));

	read_lock_bh(&security_table_lock);
	*entry = __security_table_find(net, ifindex, daddr);
	read_unlock_bh(&security_table_lock);

	if (*entry) {
		return true;
	}

	//printk(KERN_INFO "SUPERMAN: Security_Table - GetSecurityTableEntry - no entry, creating...");

	// If the entry doesn't exist, add it.
	if(!AddSecurityTableEntry(net, ifindex, daddr, SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE, 0, NULL, 0, NULL, 0, NULL, -1)) {
		return false;
	}
	else {
			read_lock_bh(&security_table_lock);
			*entry = __security_table_find(net, ifindex, daddr);
			read_unlock_bh(&security_table_lock);
	}

	//printk(KERN_INFO "SUPERMAN: Security_Table - GetSecurityTableEntry - take 2...");

	if (*entry) {
		//printk(KERN_INFO "SUPERMAN: Security_Table - GetSecurityTableEntry - success!");
		return true;
	}

	//printk(KERN_INFO "SUPERMAN: Security_Table - GetSecurityTableEntry - failure!");
	return false;
}

bool UpdateSecurityTableEntry(struct security_table_entry *e, struct net *net, uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - clearing security table entry.\n");
	ClearSecurityTableEntry(e);

	// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - updating security table entry...\n");
	e->net = net;
	e->ifindex = ifindex;
	e->daddr = daddr;
	e->flag = flag;
	if(timestamp != -1)
		e->timestamp = timestamp;

	// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - sk_len: %d, ske_len: %d, skp_len: %d\n", sk_len, ske_len, skp_len);
	if(
		((sk_len == 0) || (e->sk = kmalloc(sk_len, GFP_ATOMIC))) &&
		((ske_len == 0) || (e->ske = kmalloc(ske_len, GFP_ATOMIC))) &&
		((skp_len == 0) || (e->skp = kmalloc(skp_len, GFP_ATOMIC)))
	)
	{
		// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - malloc's succeeded.\n");
		e->sk_len = sk_len;
		e->ske_len = ske_len;
		e->skp_len = skp_len;

		// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - copying variables.\n");
		if(sk_len > 0) memcpy(e->sk, sk, sk_len); else e->sk = NULL;
		if(ske_len > 0) memcpy(e->ske, ske, ske_len); else e->ske = NULL;
		if(skp_len > 0) memcpy(e->skp, skp, skp_len); else e->skp = NULL;

		// printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - copying complete.\n");
		return true;
	}
	else
	{
		printk(KERN_INFO "Security_Table:\tUpdateSecurityTableEntry - mallocs failed.\n");
		return false;
	}
}

void ClearSecurityTableEntry(struct security_table_entry *e)
{
	if(e)
	{
		if(e->sk) kfree(e->sk);
		if(e->ske) kfree(e->ske);
		if(e->skp) kfree(e->skp);
		e->sk = NULL;
		e->ske = NULL;
		e->skp = NULL;
		e->sk_len = 0;
		e->ske_len = 0;
		e->skp_len = 0;
	}
}

bool UpdateSecurityTableEntryFlag(struct net *net, uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t timestamp)
{
	struct security_table_entry *e;

	if(GetSecurityTableEntry(net, ifindex, daddr, &e))
	{
		e->flag = flag;
		return true;
	}
	else
	{
		return UpdateOrAddSecurityTableEntry(net, ifindex, daddr, flag, 0, NULL, 0, NULL, 0, NULL, timestamp);
	}
}

bool AddSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	struct security_table_entry *e;
	bool r = false;
	// printk(KERN_INFO "Security_Table:\tAddSecurityTableEntry - creating new entry.\n");

	// printk(KERN_ERR "SUPERMAN: security_table - \t\tCreating a new entry...\n");
	e = kmalloc(sizeof(struct security_table_entry), GFP_ATOMIC);
	if (e == NULL) {
		printk(KERN_ERR "security_table: \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
		return false;
	}
	e->net = NULL;
	e->ifindex = 0;
	e->daddr = 0;
	e->flag = SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE;
	e->sk_len = 0;
	e->sk = NULL;
	e->ske_len = 0;
	e->ske = NULL;
	e->skp_len = 0;
	e->skp = NULL;
	e->timestamp = 0;

	if(!UpdateSecurityTableEntry(e, net, ifindex, daddr, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp))
	{
		RemoveSecurityTableEntry(net, ifindex, daddr);
		printk(KERN_ERR "SUPERMAN: security_table - \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
		return false;
	}

	// printk(KERN_INFO "Security_Table:\tAddSecurityTableEntry - adding entry to the table.\n");
	write_lock_bh(&security_table_lock);
	r = __security_table_add(e);
	if(r)
		security_table_len++;
	write_unlock_bh(&security_table_lock);

	if(!r)
	{
		printk(KERN_INFO "Security_Table:\tAddSecurityTableEntry - failed, cleaning up.\n");
		ClearSecurityTableEntry(e);
		kfree(e);
	}

	return r;
}

bool UpdateOrAddSecurityTableEntry(struct net *net, uint32_t ifindex, uint32_t daddr, uint8_t flag, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, int32_t timestamp)
{
	struct security_table_entry *e;

	//printk(KERN_INFO "SUPERMAN: Security_Table - UpdateOrAddSecurityTableEntry - %u.%u.%u.%u, flag = %d.\n", 0x0ff & daddr, 0x0ff & (daddr >> 8), 0x0ff & (daddr >> 16), 0x0ff & (daddr >> 24), flag);

	if(GetSecurityTableEntry(net, ifindex, daddr, &e))
	{
		// printk(KERN_INFO "Security_Table:\tUpdateOrAddSecurityTableEntry - updating existing entry.\n");

		// printk(KERN_ERR "SUPERMAN: security_table - \t\tUpdating an existing entry...\n");
		if(!UpdateSecurityTableEntry(e, net, ifindex, daddr, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp))
		{
			RemoveSecurityTableEntry(net, ifindex, daddr);
			printk(KERN_ERR "SUPERMAN: security_table - \t\t\t\"Out Of Memory\" in UpdateOrAddSecurityTableEntry\n");
			return false;
		}
		else
		{
			// printk(KERN_INFO "security_table:\tUpdateOrAddSecurityTableEntry - success.\n");
			return true;
		}
	}
	else
	{
		return AddSecurityTableEntry(net, ifindex, daddr, flag, sk_len, sk, ske_len, ske, skp_len, skp, timestamp);
	}
}



bool UpdateBroadcastKey(struct net *net, uint32_t ifindex, uint32_t sk_len, unsigned char* sk, uint32_t ske_len, unsigned char* ske, uint32_t skp_len, unsigned char* skp, bool overwrite)
{
	struct security_table_entry* entry;
	uint8_t flag = 0;

	// If we already have a valid entry and we're not being asked to overwrite it.
	if(!overwrite && GetSecurityTableEntry(net, ifindex, INADDR_BROADCAST, &entry) && entry->flag >= SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED)
	{
		//printk(KERN_INFO "Security:\tUpdateBroadcastKey - not overwriting, entry exists.\n");
		return true;
	}

	// Determine whether we have an sk.
	if(sk_len > 0 && sk != NULL)
	{
		// printk(KERN_INFO "Security:\tUpdateBroadcastKey - sk provided.\n");

		// Do we also have ske and skp?
		if(ske_len > 0 && skp_len > 0 && ske != NULL && skp != NULL)
		{
			flag = SUPERMAN_SECURITYTABLE_FLAG_SEC_VERIFIED;
			// printk(KERN_INFO "Security:\tUpdateBroadcastKey - ske and skp provided.\n");
		}
		else
		{
			flag = SUPERMAN_SECURITYTABLE_FLAG_SEC_UNVERIFIED;
			// printk(KERN_INFO "Security:\tUpdateBroadcastKey - ske and skp not provided.\n");
		}
	}
	else
	{
		flag = SUPERMAN_SECURITYTABLE_FLAG_SEC_NONE;
		// printk(KERN_INFO "Security:\tUpdateBroadcastKey - sk not provided.\n");
	}

	// printk(KERN_INFO "Security:\tUpdateBroadcastKey - requesting to update the security table entry.\n");
	return UpdateOrAddSecurityTableEntry(net, ifindex, INADDR_BROADCAST, flag, sk_len, sk, ske_len, ske, skp_len, skp, 0);
}

bool GetBroadcastKey(struct net *net, uint32_t ifindex, uint32_t* sk_len, unsigned char** sk)
{
	struct security_table_entry* entry;
	if(!GetSecurityTableEntry(net, ifindex, INADDR_BROADCAST, &entry))
		return false;
	*sk_len = entry->sk_len;
	*sk = entry->sk;
	return true;
}

int security_table_info_proc_show(struct seq_file *m, void *v)
{
	struct net *net = get_net_ns_by_pid(task_pid_nr(current));
	struct list_head *pos;

	read_lock_bh(&security_table_lock);

	seq_printf(m, "%-15s %-6s %-16s %-16s %-16s\n", "Addr", "Flag", "SK Len (bits)", "SKE Len (bits)", "SKP Len (bits)");

	list_for_each(pos, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;
		if(e->net == net)
		{
			char addr[16];
			sprintf(addr, "%u.%u.%u.%u", (0x0ff & e->daddr), (0x0ff & (e->daddr >> 8)), (0x0ff & (e->daddr >> 16)), (0x0ff & (e->daddr >> 24)));
			seq_printf(m, "%-15s %-6d %-16d %-16d %-16d\n", addr, e->flag, (e->sk_len * 8), (e->ske_len * 8), (e->skp_len * 8));
		}
	}

	read_unlock_bh(&security_table_lock);

	return 0;
}

void FlushSecurityTable(void)
{
	write_lock_bh(&security_table_lock);
	__security_table_flush();
	write_unlock_bh(&security_table_lock);
}

static int __net_init NetInitHook(struct net* net)
{
	// Add a broadcast key
	struct net_device *dev;
	for_each_netdev(net, dev)
		UpdateBroadcastKey(net, dev->ifindex, 0, NULL, 0, NULL, 0, NULL, true);

	return 0;
}

static void __net_exit NetDeInitHook(struct net* net)
{
	// Remove all security table entries related to the deinitialising network namespace.
	struct list_head *pos, *tmp;

	write_lock_bh(&security_table_lock);

	list_for_each_safe(pos, tmp, &security_table_head) {
		struct security_table_entry *e = (struct security_table_entry *)pos;
		if(e->net == net)
		{
			list_del(&e->l);
			security_table_len--;
		}
		kfree(e);
	}

	write_unlock_bh(&security_table_lock);
}

static struct pernet_operations __net_initdata superman_securitytable_net_ops = {
       .init = &NetInitHook,
       .exit = &NetDeInitHook,
};

bool InitSecurityTable(void)
{
	struct net *net;

	security_table_len = 0;
	register_pernet_subsys(&superman_securitytable_net_ops);

	for_each_net(net)
		NetInitHook(net);

	return true;
}

void DeInitSecurityTable(void)
{
	unregister_pernet_subsys(&superman_securitytable_net_ops);
	FlushSecurityTable();
}

#endif
