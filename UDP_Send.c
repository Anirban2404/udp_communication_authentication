/*MESSAGE SEND*/
#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/string.h>
#include "hmac_sample.c"
#include <linux/ktime.h>
ktime_t ktime_get(void);

#define SERVERPORT 5555
static struct socket *clientsocket=NULL;

static char hmac[40]; 
static char *key = "passphrase"; 
//static char *mystring = "22"; 

static int __init client_init( void )
{
	int len;
	char buf[64];

	char message[]= {"hello world"};

	char outmessage[51];

	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	struct sockaddr_in to;
	printk(KERN_ERR "sendthread initialized\n");
	if( sock_create( PF_INET,SOCK_DGRAM,IPPROTO_UDP,&clientsocket)<0 ){
		printk( KERN_ERR "server: Error creating clientsocket.n" );
		return -EIO;
	}

	/*HMAC*/
	printk(KERN_INFO "[CRYPTO] -> Successfully loaded crypto module.\n");
	memset(&outmessage[0], 0, sizeof(outmessage));

	printk("message len: %i message: %s\n", strlen(message), message); 

	strncpy(outmessage,message,11);
	printk("message len: %i inmessage: %s\n", strlen(outmessage), outmessage);    

	ktime_t start, end;
	s64 actual_time;
	printk(KERN_INFO "[CRYPTO] -> Successfully loaded crypto module.\n");
	start = ktime_get(); 
	hmac_sha1(outmessage, 11, key, strlen(key),hmac, sizeof(hmac)); 
	end = ktime_get();
	// hmac_sha1(key, strlen(key), outmessage, 11, hmac, sizeof(hmac));
	printk("message len: %i  FINAL MAC:%s \n",strlen(hmac), hmac);
	actual_time = ktime_to_ns(ktime_sub(end, start));
	printk("Time taken for function() execution: %d\n",(int)actual_time);
	int temp=0;
	int ptr = 11;
	while(temp<40)
	{   
		outmessage[ptr++]=  hmac[temp++];
	}
	memset(&buf[0],0,sizeof(buf));
	memset(&message[0], 0, sizeof(message));

	printk("message len: %i hmacmessage: %s\n", strlen(outmessage), outmessage); 

	memset(&to,0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = in_aton( "192.168.56.103" );  
	/* destination address */
	to.sin_port = htons( (unsigned short) SERVERPORT );
	memset(&msg,0,sizeof(msg));
	msg.msg_name = &to;
	msg.msg_namelen = sizeof(to);
	//Sending message
	iov.iov_base = outmessage;
	iov.iov_len  = 51;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;
	oldfs = get_fs();
	set_fs( KERNEL_DS );

	int i = 0;
	while ( i < 1){
		i++;
		len = sock_sendmsg( clientsocket, &msg, 51 );
	}

	set_fs( oldfs );
	printk( KERN_ERR "sock_sendmsg returned: %d\n", len);
	return 0;
}

static void __exit client_exit( void )
{
	if( clientsocket )
		sock_release( clientsocket );
}

module_init( client_init );
module_exit( client_exit );
MODULE_LICENSE("GPL");
