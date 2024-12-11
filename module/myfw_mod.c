#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/timer.h>
#include <linux/spinlock.h>

#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>
#include <net/ip.h>

// dev numbers
#define MYMAJOR	200
// Protocol numbers
#define TCP			6
#define	UDP			17
#define ICMP		1
#define ANY			-1
#define ICMP_PORT	65530

#define CONNECTION_RECORD_SIZE 24 // Connection Structure Size
#define MAX_RULE_NUM	50
#define MAX_LOG_NUM		100
#define MAX_NAT_NUM 	1000
#define HASH_SIZER		20
#define CONNECT_TIME	60
// chrdev ops
#define OP_WRITE_RULE	0
#define OP_GET_CONNECT	1
#define OP_GET_LOG		2
#define OP_GET_NAT		3



// IP format
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[3], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[0]

// dev def
dev_t	devID;
struct cdev 	cdev;
struct class    *D_class;
struct device   *D_device;

// rules struct
typedef struct {
    unsigned src_ip;
	unsigned dst_ip;
	unsigned src_mask;
	unsigned dst_mask;
	int src_port;
	int dst_port;
	int protocol;
	int action;
	int log;
} Rule;
// rules table
static Rule rules[MAX_RULE_NUM];
// rules nums
static int rule_num = 0;

// Log struct
typedef struct{
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int action;
} Log;
// Log tables
static Log logs[MAX_LOG_NUM];
// Log nums
static int log_num = 0;


// Connected struct
typedef struct con{
	unsigned src_ip;
	unsigned dst_ip;
	int src_port;
	int dst_port;
	int protocol;
	int index;
	char timer1;
	struct hlist_node node;
}Connection;

DECLARE_HASHTABLE(hashTable, HASH_SIZER);

// Connected numbers
static int connection_num = 0;

// hash lock
spinlock_t my_lock;
// op（0 write rules 1 get connection table，2 get logs)
static unsigned op_flag;
// read write buffer
static char databuf[20480];


// hook in
unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
// hook out
unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
// open chardev
static int datadev_open(struct inode *inode, struct file *filp);
// read chardev
static ssize_t datadev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
// write chardev
static ssize_t datadev_write(struct file *file, const char __user *user, size_t size, loff_t *ppos);
// check in hashtable
int is_in_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol);
// insert table
void insert_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol,unsigned index);

void add_log(Rule *p);
// update connection table
void time_out(struct timer_list *timer);

void print_rules(void);

// void print_connections(void);

static unsigned get_hash(int k);
// check all pkg
bool check_pkg(struct sk_buff *skb);

// netfilter hook sturcture
static struct nf_hook_ops hook_in_ops = {
    .hook		= hook_in,				// Hook processing function
    .pf         = PF_INET,              // Protocol family type
    .hooknum    = NF_INET_PRE_ROUTING,	// Hook registration point
    .priority   = NF_IP_PRI_FIRST       // Priority level
};

static struct nf_hook_ops hook_out_ops = {
    .hook		= hook_out,				// Hook processing function
    .pf         = PF_INET,              // Protocol family type
    .hooknum    = NF_INET_POST_ROUTING,	// Hook registration point
    .priority   = NF_IP_PRI_FIRST       // Priority level
};

static struct timer_list connect_timer;

static const struct file_operations datadev_fops = {
	.open		= datadev_open,			// open chardev
	.read		= datadev_read,			// read chardev
	.write		= datadev_write,		// write chardev
};





unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	bool flag = check_pkg(skb);
	if (flag) {
		return NF_ACCEPT;
	} else {
		return NF_DROP;
	}
}

unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	bool flag = check_pkg(skb);
	if (flag) {
		return NF_ACCEPT;
	} else {
		return NF_DROP;
	}
}

static int datadev_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "datadev open\n");
	return 0;
}

static ssize_t datadev_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
	int ret = 0;

	// get connection table
	if (op_flag == OP_GET_CONNECT) {

		Connection *cur;
		unsigned bkt;
		// return connection table size
		ret = connection_num * (sizeof(Connection) - 4);
		if (ret > size) {
			printk("Connection: Read Overflow\n");
			return size;
		}
		// wait unlock
		spin_lock(&my_lock);
		int d, i=0;
		hash_for_each (hashTable, bkt, cur, node) {
			unsigned int src_ip = cur->src_ip;
			unsigned int dst_ip = cur->dst_ip;
			int src_port = cur->src_port;
			int dst_port = cur->dst_port;
			int protocol = cur->protocol;
			unsigned int timer1 = cur->timer1;

			if ((i + 1) * CONNECTION_RECORD_SIZE > sizeof(databuf)) {
				// Buffer Overflow
				break;
			}

			memcpy(&databuf[i * CONNECTION_RECORD_SIZE], &src_ip, sizeof(unsigned int));
			memcpy(&databuf[i * CONNECTION_RECORD_SIZE + 4], &dst_ip, sizeof(unsigned int));
			memcpy(&databuf[i * CONNECTION_RECORD_SIZE + 8], &src_port, sizeof(int));
			memcpy(&databuf[i * CONNECTION_RECORD_SIZE + 12], &dst_port, sizeof(int));
			memcpy(&databuf[i * CONNECTION_RECORD_SIZE + 16], &protocol, sizeof(int));
			memcpy(&databuf[i * CONNECTION_RECORD_SIZE + 20], &timer1, sizeof(unsigned int));

			i++;
		
		}

		// unlock
		spin_unlock(&my_lock);

		copy_to_user(buf, databuf, ret);
		printk("Connection: Read %d bytes\n", ret);
	}
	// get Logs table
	else if (op_flag == OP_GET_LOG) {
		ret = log_num * sizeof(Log);
		if (ret > size) {
			printk("Log: Read Overflow\n");
			return size;
		}

		memcpy(databuf, logs, ret);
		copy_to_user(buf, databuf, ret);
		printk("Log: Read %d bytes\n", ret);
	}

	return ret;
}

static ssize_t datadev_write(struct file *file, const char __user *user, size_t size, loff_t *ppos) {
	if (size > 20480) {
		printk("Write Overflow\n");
		return 20480;
	}

	copy_from_user(databuf, user, size);

	int opt = 0x03 & databuf[size-1];

	if (opt == OP_WRITE_RULE) {
		op_flag = 0;
		rule_num = (size-1) / sizeof(Rule);
		printk("Get %d rules\n", rule_num);
		memcpy(rules, databuf+1, size-1);
		print_rules();
	}
	else if (opt == OP_GET_CONNECT) {
		op_flag = OP_GET_CONNECT;
		printk("Write Connections\n");
	}
	else if (opt == OP_GET_LOG) {
		op_flag = OP_GET_LOG;
		printk("Write Log\n");
	}
	else if (opt == OP_GET_NAT) {
		op_flag = OP_GET_NAT;
		printk("Write NAT\n");
	}

	return size;
}

int is_in_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol) {
	unsigned scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
	unsigned pos = get_hash(scode);


	Connection *entry;
	spin_lock(&my_lock);  // lock

	hash_for_each (hashTable, pos, entry, node) {
		if (entry->src_ip == src_ip && entry->dst_ip == dst_ip && 
			entry->src_port == src_port && entry->dst_port == dst_port && 
			entry->protocol == protocol) {
			entry->timer1 = CONNECT_TIME;
			spin_unlock(&my_lock); // unlock and return
			return -1;
		}
	}

	spin_unlock(&my_lock);  // unlock
    return pos; 

}

void insert_hashTable(unsigned src_ip,unsigned dst_ip,int src_port,int dst_port,int protocol,unsigned index) {
	Connection *p = (Connection *)kmalloc(sizeof(Connection), GFP_ATOMIC);
	
	p->src_ip = src_ip;
	p->dst_ip = dst_ip;
	p->src_port = src_port;
	p->dst_port = dst_port;
	p->protocol = protocol;
	p->index = index;
	p->timer1 = CONNECT_TIME;

	spin_lock(&my_lock);  // lock
	hash_add(hashTable, &p->node, index);
	spin_unlock(&my_lock); // unlock

	++connection_num;
}

void add_log(Rule *p) {
	logs[log_num].src_ip 	= p->src_ip;
	logs[log_num].dst_ip 	= p->dst_ip;
	logs[log_num].src_port 	= p->src_port;
	logs[log_num].dst_port 	= p->dst_port;
	logs[log_num].protocol 	= p->protocol;
	logs[log_num].action 	= p->action;
	
	log_num++;
	if (log_num == MAX_LOG_NUM)
		log_num = 0;
}

void time_out(struct timer_list *timer) {
	unsigned bkt;
	Connection *cur;
	spin_lock(&my_lock);
	hash_for_each (hashTable, bkt, cur, node) {
		cur->timer1--;
		if (cur->timer1 <= 0)
			hash_del(&cur->node);
	}
	spin_unlock(&my_lock);

	mod_timer(timer, jiffies + HZ); 
}

void print_rules(void) {
	int i = 0;
	for(i=0; i<rule_num; ++i) {
		// srcIP & dstIP
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].src_ip), rules[i].src_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].dst_ip), rules[i].dst_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].src_mask), rules[i].src_mask);
		printk(NIPQUAD_FMT " ", NIPQUAD(rules[i].dst_mask), rules[i].dst_mask);

		// srcPort
		if (rules[i].src_port != ANY)
			printk("%d ", rules[i].src_port);
		else 
			printk("any ");
		// dstPort
		if (rules[i].dst_port != ANY)
			printk("%d ", rules[i].dst_port);
		else 
			printk("any ");
		// Protocol
		if (rules[i].protocol == TCP)
			printk("TCP ");
		else if (rules[i].protocol == UDP)
			printk("UDP ");
		else if (rules[i].protocol == ICMP)
			printk("ICMP ");
		
		// action
		if (rules[i].action)
			printk("accept ");
		else
			printk("deny ");
		
		// log
		if (rules[i].log)
			printk("loged\n");
		else 
			printk("unloged\n");
	}
}

/*
void print_connections(void) {
	Connection *p = conHead.next;


	while(hashLock)
		;

	hashLock = 1;

	printk("************************************************\n");
	while (p != &conEnd) {
		// srcIP & dstIP
		printk(NIPQUAD_FMT " ", NIPQUAD(p->src_ip), p->src_ip);
		printk(NIPQUAD_FMT " ", NIPQUAD(p->dst_ip), p->dst_ip);
		// port
		printk("%u %u ", p->src_port, p->dst_port);
		// protocol
		if (p->protocol == TCP)
			printk("TCP ");
		else if (p->protocol == UDP)
			printk("UDP ");
		else if (p->protocol == ICMP)
			printk("ICMP ");
		// left time
		printk("%u\n", hashTable[p->index]);
		
		p = p->next;
	}
	printk("************************************************\n");


	hashLock = 0;
}
*/

static unsigned get_hash(int k) {
	unsigned a, b, c=4;
    a = b = 0x9e3779b9;
    a += k;
	a -= b; a -= c; a ^= (c>>13); 
	b -= c; b -= a; b ^= (a<<8); 
	c -= a; c -= b; c ^= (b>>13); 
	a -= b; a -= c; a ^= (c>>12);  
	b -= c; b -= a; b ^= (a<<16); 
	c -= a; c -= b; c ^= (b>>5); 
	a -= b; a -= c; a ^= (c>>3);  
	b -= c; b -= a; b ^= (a<<10); 
	c -= a; c -= b; c ^= (b>>15); 
  
    return c%(1 << (HASH_SIZER));
}

bool check_pkg(struct sk_buff *skb) {
	if(!skb)
		return true;
	
	int i = 0;
	struct iphdr *ip = ip_hdr(skb);
	
	Rule pkg;
	pkg.src_ip = ntohl(ip->saddr);
	pkg.dst_ip = ntohl(ip->daddr);
	pkg.src_mask = pkg.dst_mask = 0xffffffff;
	
	int syn;
	if (ip->protocol == TCP) {
		struct tcphdr *tcp = tcp_hdr(skb);
		pkg.src_port = ntohs(tcp->source);
		pkg.dst_port = ntohs(tcp->dest);
		pkg.protocol = TCP;

		if ((tcp->syn) && (!tcp->ack))
			syn = 1;
		else
			syn = 0;
	}
	else if (ip->protocol == UDP) {
		struct udphdr *udp = udp_hdr(skb);
		pkg.src_port = ntohs(udp->source);
		pkg.dst_port = ntohs(udp->dest);
		pkg.protocol = UDP;

		syn = 2;
	}
	else if (ip->protocol == ICMP) {
		pkg.src_port = ICMP_PORT;
		pkg.dst_port = ICMP_PORT;
		pkg.protocol = ICMP;

		syn = 3;
	}
	else {
		return true;
	}

	int pos = is_in_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol);
	if (pos == -1) {
		return true;
	}
	else {
		for(i=0; i<rule_num; ++i) {
			if ((rules[i].src_ip & rules[i].src_mask) != (pkg.src_ip & rules[i].src_mask)) {
				continue;
			}
			if ((rules[i].dst_ip & rules[i].dst_mask) != (pkg.dst_ip & rules[i].dst_mask)) {
				continue;
			}
			if ((rules[i].protocol != ANY) && (rules[i].protocol != pkg.protocol)) {
				continue;
			}
			if ((rules[i].src_port != ANY) && (rules[i].src_port != pkg.src_port)) {
				continue;
			}
			if ((rules[i].dst_port != ANY) && (rules[i].dst_port != pkg.dst_port)) {
				continue;
			}

			if (rules[i].log) {
				printk("Match rule %d ", i);

				if (rules[i].action)
					printk("Accept\n");
				else
					printk("Drop\n");
				
				add_log(&rules[i]);
			}

			if (rules[i].action) {
				insert_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol, pos);
				return true;
			}
			else {
				return false;
			}
		}
		// Default allowed
		insert_hashTable(pkg.src_ip, pkg.dst_ip, pkg.src_port, pkg.dst_port, pkg.protocol, pos);
		return true;
	}
}

void addRules_test(void) {
	rules[rule_num].src_ip	= 0;
	rules[rule_num].src_mask= 0;
	rules[rule_num].dst_ip	= 3232241537;
	rules[rule_num].dst_mask= 0xFFFFFFFF;
	rules[rule_num].src_port= ANY;
	rules[rule_num].dst_port= 80;
	rules[rule_num].protocol= TCP;
	rules[rule_num].action	= false;
	rules[rule_num].log		= true;
	++rule_num;
}

static int __init myfirewall_init(void) {

	hash_init(hashTable);  // init hashtble
	spin_lock_init(&my_lock);
	cdev_init(&cdev, &datadev_fops);
	alloc_chrdev_region(&devID, 2, 255, "myfw");
	printk(KERN_INFO "MAJOR Number is %d\n", MAJOR(devID));
	printk(KERN_INFO "MINOR Number is %d\n", MINOR(devID));
	cdev_add(&cdev, devID, 255);

	D_class = class_create("Myfw");
	D_device = device_create(D_class, NULL, devID, NULL, "myfw");


	timer_setup(&connect_timer, time_out, 0);
	mod_timer(&connect_timer, jiffies + HZ);
	
	nf_register_net_hook(&init_net, &hook_in_ops);
	nf_unregister_net_hook(&init_net, &hook_out_ops);

	printk("Myfw start\n");

	// addRules_test();
	print_rules();


	return 0;
}

static void __exit myfirewall_exit(void) {

	Connection *entry;
    struct hlist_node *tmp;
    int bkt;

    // clear hash table
    hash_for_each_safe(hashTable, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }

	device_destroy(D_class, devID);
	class_destroy(D_class);
	cdev_del(&cdev);
	unregister_chrdev_region(devID, 255);
	del_timer(&connect_timer);

	nf_unregister_net_hook(&init_net, &hook_in_ops);
	nf_unregister_net_hook(&init_net, &hook_out_ops);

	printk("Myfw exit\n");
}

module_init(myfirewall_init);
module_exit(myfirewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DAchilles");
MODULE_DESCRIPTION("A firewall module");
MODULE_VERSION("V1.0");
