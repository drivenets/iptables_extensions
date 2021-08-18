
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/l3mdev.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "xt_novrf.h"

MODULE_AUTHOR("Lahav Schlesinger <lschlesinger@drivenets.com>");
MODULE_DESCRIPTION("Netfilter module to match interfaces on the default VRF");
MODULE_LICENSE("GPL");

/**
 * Shamelessly stolen from 'net/netfilter/x_tables.c'
 */
static char*
textify_hooks(char *buf, size_t size, unsigned int mask, uint8_t nfproto) {
    static const char *const inetbr_names[] = {
        "PREROUTING", "INPUT", "FORWARD",
        "OUTPUT", "POSTROUTING", "BROUTING",
    };
    static const char *const arp_names[] = {
        "INPUT", "FORWARD", "OUTPUT",
    };
    const char *const *names;
    unsigned int i, max;
    char *p = buf;
    bool np = false;
    int res;

    names = (nfproto == NFPROTO_ARP) ? arp_names : inetbr_names;
    max   = (nfproto == NFPROTO_ARP) ? ARRAY_SIZE(arp_names) : ARRAY_SIZE(inetbr_names);
    *p = '\0';
    for (i = 0; i < max; ++i) {
        if (!(mask & (1 << i)))
            continue;
        res = snprintf(p, size, "%s%s", np ? "/" : "", names[i]);
        if (res > 0) {
            size -= res;
            p += res;
        }
        np = true;
    }

    return buf;
}


static bool
novrf_mt(const struct sk_buff *skb, struct xt_action_param *par) {
    const struct xt_novrf_mtinfo *info = par->matchinfo;
    const unsigned int mode_flags = info->mode_flags;

    if (mode_flags & XT_NOVRF_IN_DEV) {
        struct net_device *dev = par->state->in;
        if (! dev) {
            /** Shouldn't get here - Verified at 'novrf_mt_check()' */
            pr_crit(KBUILD_MODNAME ": Running in hook %d with mode_flags=%u, but the input device is NULL\n",
                    par->state->hook,
                    mode_flags);
            par->hotdrop = 1;
            return false;
        }

        /** If wanting default VRF, don't match VRF interfaces. */
        if ((netif_is_l3_master(dev) || netif_is_l3_slave(dev)) ^
            !!(mode_flags & XT_NOVRF_IN_DEV_INV)) {
                return false;
        }
    }

    if (mode_flags & XT_NOVRF_OUT_DEV) {
        struct net_device *dev = par->state->out;
        if (! dev) {
            /** Shouldn't get here - Verified at 'novrf_mt_check()' */
            pr_crit(KBUILD_MODNAME ": Running in hook %d with mode_flags=%u, but the output device is NULL\n",
                    par->state->hook,
                    mode_flags);
            par->hotdrop = 1;
            return false;
        }

        /** If wanting default VRF, don't match VRF interfaces. */
        if ((netif_is_l3_master(dev) || netif_is_l3_slave(dev)) ^
            !!(mode_flags & XT_NOVRF_OUT_DEV_INV)) {
                return false;
        }
    }

    return true;
}

static int novrf_mt_check(const struct xt_mtchk_param *par) {
    const struct xt_novrf_mtinfo *info = par->matchinfo;
    const unsigned int mode_flags = info->mode_flags;
    const unsigned int requested_hooks = par->hook_mask;
    const unsigned int no_input_hooks = (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_POST_ROUTING);
    const unsigned int no_output_hooks = (1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_LOCAL_IN);
    char requested[64];

    pr_info(KBUILD_MODNAME ": Adding new rule with mode_flags=%u, for hooks=%s\n",
            mode_flags,
            textify_hooks(requested, sizeof(requested), requested_hooks,
                          par->family));

    /** First, check the flags consistency (can't have invert bit without the non-inverted) */
    if ((mode_flags & XT_NOVRF_IN_DEV_INV) && (~mode_flags & XT_NOVRF_IN_DEV)) {
        pr_err(KBUILD_MODNAME ": Inverted input device flag is missing the non-inverted flag\n");
        return -EINVAL;
    }
    if ((mode_flags & XT_NOVRF_OUT_DEV_INV) && (~mode_flags & XT_NOVRF_OUT_DEV)) {
        pr_err(KBUILD_MODNAME ": Inverted output device flag is missing the non-inverted flag\n");
        return -EINVAL;
    }

    /**
     * Second, check if the requested device "direction" makes sense for the requested hooks.
     * e.g. In "PRE_ROUTING" there's only the input device, so XT_NOVRF_OUT_DEV
     *   is meaningless there.
     *
     * The full list is:
     * PRE_ROUTING, LOCAL_IN   -> Only input
     * FORWARD                 -> Both input and output
     * LOCAL_OUT, POST_ROUTING -> Only output
     */
    if ((mode_flags & XT_NOVRF_IN_DEV) && (requested_hooks & no_input_hooks)) {
        char allowed[64];

        pr_info(KBUILD_MODNAME ": Match used from hooks %s, but input device is valid only from %s\n",
                requested,
                textify_hooks(allowed, sizeof(allowed),
                              ~(~0u << NF_INET_NUMHOOKS) & ~no_input_hooks,
                              par->family));
        return -EINVAL;
    }
    if ((mode_flags & XT_NOVRF_OUT_DEV) && (requested_hooks & no_output_hooks)) {
        char allowed[64];

        pr_info(KBUILD_MODNAME ": Match used from hooks %s, but output device is valid only from %s\n",
                requested,
                textify_hooks(allowed, sizeof(allowed),
                              ~(~0u << NF_INET_NUMHOOKS) & ~no_output_hooks,
                              par->family));
        return -EINVAL;
    }

    return 0;
}

static void novrf_mt_destroy(const struct xt_mtdtor_param *par) {
    const struct xt_novrf_mtinfo *info = par->matchinfo;
    const unsigned int mode_flags = info->mode_flags;

    pr_info(KBUILD_MODNAME ": Rule with mode_flags=%u removed\n",
            mode_flags);
}


static struct xt_match novrf_mt_reg __read_mostly = {
    .name       = "novrf",
    .revision   = 0,
    .family     = NFPROTO_UNSPEC,
    .checkentry = novrf_mt_check,
    .match      = novrf_mt,
    .destroy    = novrf_mt_destroy,
    .matchsize  = sizeof(struct xt_novrf_mtinfo),
    .me         = THIS_MODULE,
};

static int __init novrf_mt_init(void) {
    int ret;

    ret = xt_register_match(&novrf_mt_reg);
    if (ret) {
        pr_err(KBUILD_MODNAME ": Failed registering match. err = %d\n",
               ret);
        return ret;
    }

    pr_info(KBUILD_MODNAME ": Successfully loaded module!\n");
    return 0;
}

static void __exit novrf_mt_exit(void) {
    pr_info(KBUILD_MODNAME ": Unloading module\n");
    xt_unregister_match(&novrf_mt_reg);
}

module_init(novrf_mt_init);
module_exit(novrf_mt_exit);
