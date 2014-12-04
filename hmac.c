/*HMAC*/
#include <crypto/algapi.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/ktime.h>
ktime_t ktime_get(void);

#define MAX_DIGEST_SIZE  20

static char hmac_sha1(char *plain_text, unsigned int plain_text_size,
					  char *key, unsigned int key_size,
					  char *hash_out, size_t outlen)
{
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	int ret;
	void *hash_buf; 
	int len = 20; 
	char hash_tmp[20];
	char *result = hash_tmp; 

	/* Set hash output to 0 initially */
	memset(hash_out, 0, outlen);

	tfm = crypto_alloc_hash("hmac(sha1)", 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR
			"failed to load transform for hmac(sha1): %ld\n",
			PTR_ERR(tfm));
		return NULL;
	}

	desc.tfm = tfm;
	desc.flags = 0;

	hash_buf=kzalloc(plain_text_size,GFP_KERNEL);
	if(!hash_buf)
	{ 
		printk(KERN_ERR "hmac_sha1: failed to kzalloc hash_buf");
		goto out;
	} 
	memcpy(hash_buf,plain_text,plain_text_size); 

	result = kzalloc(MAX_DIGEST_SIZE, GFP_KERNEL);
	if (!result) {
		printk(KERN_ERR "out of memory!\n");
		goto out;
	}

	sg_set_buf(&sg,hash_buf,plain_text_size); 

	ret = crypto_hash_setkey(tfm, key, key_size);
	if (ret) {
		printk(KERN_ERR "setkey() failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

	ret = crypto_hash_digest(&desc, &sg, plain_text_size, result);
	if (ret) {
		printk(KERN_ERR "digest () failed ret=%d\n", ret);
		kfree(result);
		result = NULL;
		goto out;
	}

	while (len--) {
		snprintf(hash_out, outlen, "%02x", (*result++ & 0x0FF));
		hash_out += 2;
	}

out:
	crypto_free_hash(tfm);
	return result;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HMAC algorithm");
