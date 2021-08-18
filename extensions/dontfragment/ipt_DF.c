#include <linux/module.h>
#include <linux/kernel.h>
#include <net/ip.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include "ipt_DF.h"

MODULE_AUTHOR("Semyon Verchenko");
MODULE_DESCRIPTION("Netfilter module to set/reset DF flag");
MODULE_LICENSE("Dual BSD/GPL");

static int df_tg_check(const struct xt_tgchk_param *param)
{
	return 0;
}

static unsigned int df_tg(struct sk_buff *skb, const struct xt_action_param *param)
{
	__u32 check;
	struct iphdr *iph = NULL;
	df_mode mode = ((struct xt_df_tginfo *)(param->targinfo))->mode;
	__u16 old_frag_off, new_frag_off;

	/* make_writable might invoke copy-on-write, so fetch iph afterwards */
	if (!skb_make_writable(skb, sizeof(struct iphdr))){
		printk(KERN_ERR "DF: Error making skb writable\n");
		return NF_DROP;
	}
	iph = ip_hdr(skb);

	new_frag_off = old_frag_off = ntohs(iph->frag_off);

	if (mode == IPT_DF_SET)
		new_frag_off |= IP_DF;
	else if (mode == IPT_DF_RESET)
		new_frag_off &= ~IP_DF;

	if (old_frag_off == new_frag_off)
		return XT_CONTINUE;

	check = ntohs((__force __be16)iph->check);
	check += old_frag_off;
	if ((check + 1) >> 16) check = (check + 1) & 0xffff;
	check -= new_frag_off;
	check += check >> 16;

	iph->frag_off = ntohs(new_frag_off);
	iph->check = (__force __sum16) htons(check);
	return XT_CONTINUE;
}

static struct xt_target ipt_df = {
	.name = "DF",
	.target = df_tg,
	.table = "mangle",
	.family = NFPROTO_IPV4,
	.targetsize = sizeof(struct xt_df_tginfo),
	.checkentry = df_tg_check,
	.me = THIS_MODULE,
};

static int __init df_tg_init(void)
{
	printk(KERN_INFO "DF loading\n");
	return xt_register_target(&ipt_df);
}

void __exit df_tg_exit(void)
{
	printk(KERN_INFO "DF unloading\n");
	xt_unregister_target(&ipt_df);
}

module_init(df_tg_init);
module_exit(df_tg_exit);
