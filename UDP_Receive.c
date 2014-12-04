
/*MESSAGE RECEIVE*/

#include <linux/module.h> 
#include <linux/init.h> 
#include <linux/in.h> 
#include <net/sock.h> 
#include <linux/skbuff.h> 
#include <linux/delay.h> 
#include <linux/inet.h> 
#include <linux/string.h> 
#include "hmac.c" 

#define SERVER_PORT 5555 
static struct socket *udpsocket=NULL; 
static struct socket *clientsocket=NULL; 

static char hmac[40]; 
static char *key = "passphrase"; 

static DECLARE_COMPLETION( threadcomplete ); 
struct workqueue_struct *wq; 

struct wq_wrapper{ 
	struct work_struct worker; 
	struct sock * sk; 
}; 

struct wq_wrapper wq_data; 

static void cb_data(struct sock *sk, int bytes){ 
	wq_data.sk = sk; 
	queue_work(wq, &wq_data.worker); 
} 

void send_answer(struct work_struct *data){ 
	struct  wq_wrapper * foo = container_of(data, struct  wq_wrapper, worker); 
	int len = 0; 
	/* as long as there are messages in the receive queue of this socket*/ 
	while((len = skb_queue_len(&foo->sk->sk_receive_queue)) > 0){ 
		struct sk_buff *skb = NULL; 
		char temp_message[20]; 
		char inmessage[51]; 
		char message[51]; 
		char check[41]; 
		/* receive packet */ 
		skb = skb_dequeue(&foo->sk->sk_receive_queue); 

		printk("message len: %i message: %s\n", skb->len - 8, skb->data +8); /*8 for udp header*/ 
		memset(&inmessage[0], 0, sizeof(inmessage));    
		memset(&check[0], 0, sizeof(check));  
		memset(&temp_message[0], 0, sizeof(temp_message));   
		memset(&message[0], 0, sizeof(message));    
		strncpy(inmessage,skb->data +8,51);     

		strncpy(temp_message,inmessage,11); 
		printk("message len: %i inmessage: %s\n", strlen(inmessage), inmessage);     
		printk("message len: %i temp_message: %s\n", strlen(temp_message), temp_message); 
		printk(KERN_INFO "[CRYPTO] -> Successfully loaded crypto module.\n"); 
		hmac_sha1(temp_message, 11, key, strlen(key),hmac, sizeof(hmac)); 
		//hmac_sha1(key, strlen(key), temp_message, 11, hmac, sizeof(hmac)); 
		printk("message len: %i  FINAL MAC:%s \n",strlen(hmac), hmac); 

		strncpy(message,inmessage,51); 
		int temp=0; 
		int ptr = 0; 

		for (temp=11,ptr=0;temp<51;temp++,ptr++) 
		{	 
			check[ptr]=inmessage[temp]; 
		} 

		check[41]='\0'; 
		printk("message len: %i  Recieved MAC:%s \n",strlen(check), check); 
		if (strncmp(check,  hmac,40) == 0) 
		{ 
			printk("Cheers: %s matched with %s\n", check, hmac); 
		} 
		else 
		{ 
			printk("Got %s instead of %s\n", check, hmac); 

		} 

		kfree_skb(skb); 
	} 
} 

static int __init server_init( void ) 
{ 
	struct sockaddr_in server; 
	int servererror; 
	printk("INIT MODULE\n"); 
	/* socket to receive data */ 
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &udpsocket) < 0) { 
		printk( KERN_ERR "server: Error creating udpsocket.n" ); 
		return -EIO; 
	} 
	server.sin_family = AF_INET; 
	server.sin_addr.s_addr = INADDR_ANY; 
	server.sin_port = htons( (unsigned short)SERVER_PORT); 

	servererror = udpsocket->ops->bind(udpsocket, (struct sockaddr *) &server, sizeof(server )); 
	if (servererror) { 
		sock_release(udpsocket); 
		return -EIO; 
	} 
	udpsocket->sk->sk_data_ready = cb_data; 

	/* create work queue */     
	INIT_WORK(&wq_data.worker, send_answer); 
	wq = create_singlethread_workqueue("myworkqueue"); 
	if (!wq){ 
		return -ENOMEM; 
	} 

	return 0; 
} 

static void __exit server_exit( void ) 
{ 
	if (udpsocket) 
		sock_release(udpsocket); 
	if (clientsocket) 
		sock_release(clientsocket); 

	if (wq) { 
		flush_workqueue(wq); 
		destroy_workqueue(wq); 
	} 
	printk("EXIT MODULE"); 
} 

module_init(server_init); 
module_exit(server_exit); 
MODULE_LICENSE("GPL");

