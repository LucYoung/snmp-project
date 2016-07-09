#include <linux/types.h>

static inline unsigned short from32to16(unsigned int x);
static unsigned int do_csum(const unsigned char *buff, int len);
__sum16 ip_fast_csum(const void *iph, unsigned int ihl);