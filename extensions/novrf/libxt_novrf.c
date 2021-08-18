
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "xt_novrf.h"

#define __maybe_unused __attribute__((__unused__))

enum {
    O_NOVRF_IN_DEV = 0,
    O_NOVRF_OUT_DEV,
};

static const struct xt_option_entry novrf_opts[] = {
    {.name = "input",  .type = XTTYPE_NONE, .id = O_NOVRF_IN_DEV,  .flags = XTOPT_INVERT },
    {.name = "output", .type = XTTYPE_NONE, .id = O_NOVRF_OUT_DEV, .flags = XTOPT_INVERT },
    XTOPT_TABLEEND,
};


static void novrf_help(void) {
    printf("novrf match options:\n"
           " [!] --input \tinput device is in default VRF\n"
           " [!] --output\toutput device is in default VRF\n");
}

static void novrf_print(__maybe_unused const void *entry, const struct xt_entry_match *match, __maybe_unused int numeric) {
    const struct xt_novrf_mtinfo *info = (struct xt_novrf_mtinfo*)match->data;
    const unsigned int mode_flags = info->mode_flags;

    printf(" novrf");

    if (mode_flags & XT_NOVRF_IN_DEV) {
        if (mode_flags & XT_NOVRF_IN_DEV_INV) {
            printf(" ! input");
        } else {
            printf(" input");
        }
    }
    if (mode_flags & XT_NOVRF_OUT_DEV) {
        if (mode_flags & XT_NOVRF_OUT_DEV_INV) {
            printf(" ! output");
        } else {
            printf(" output");
        }
    }
}

static void novrf_save(__maybe_unused const void *entry, const struct xt_entry_match *match) {
    const struct xt_novrf_mtinfo *info = (struct xt_novrf_mtinfo*)match->data;
    const unsigned int mode_flags = info->mode_flags;

    if (mode_flags & XT_NOVRF_IN_DEV) {
        if (mode_flags & XT_NOVRF_IN_DEV_INV) {
            printf(" ! --input");
        } else {
            printf(" --input");
        }
    }
    if (mode_flags & XT_NOVRF_OUT_DEV) {
        if (mode_flags & XT_NOVRF_OUT_DEV_INV) {
            printf(" ! --output");
        } else {
            printf(" --output");
        }
    }
}

static void novrf_parse(struct xt_option_call *cb) {
    struct xt_novrf_mtinfo *info = (struct xt_novrf_mtinfo*)cb->data;

    xtables_option_parse(cb);
    switch(cb->entry->id) {
        case O_NOVRF_IN_DEV:
            info->mode_flags |= XT_NOVRF_IN_DEV;
            if (cb->invert) {
                info->mode_flags |= XT_NOVRF_IN_DEV_INV;
            }
            break;

        case O_NOVRF_OUT_DEV:
            info->mode_flags |= XT_NOVRF_OUT_DEV;
            if (cb->invert) {
                info->mode_flags |= XT_NOVRF_OUT_DEV_INV;
            }
            break;
    }
}


static struct xtables_match novrf_mt_reg = {
    .family         = NFPROTO_UNSPEC,
    .name           = "novrf",
    .version        = XTABLES_VERSION,
    .size           = XT_ALIGN(sizeof(struct xt_novrf_mtinfo)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_novrf_mtinfo)),
    .help           = novrf_help,
    .print          = novrf_print,
    .save           = novrf_save,
    .x6_parse       = novrf_parse,
    .x6_options     = novrf_opts,
};

void _init(void) {
    xtables_register_match(&novrf_mt_reg);
}
