#include <stdio.h>
#include <xtables.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include "ipt_DF.h"

#define __maybe_unused __attribute__((__unused__))

enum {
	O_DF_SET = 0,
	O_DF_RESET,
	F_DF_SET = 1 << O_DF_SET,
	F_DF_RESET = 1 << O_DF_RESET,
	F_ANY = F_DF_SET | F_DF_RESET,
};

static const struct xt_option_entry DF_opts[] = {
	{.name = "set", .type = XTTYPE_NONE, .id = O_DF_SET,
	 .excl = F_ANY },
	{.name = "reset", .type = XTTYPE_NONE, .id = O_DF_RESET,
	 .excl = F_ANY },
	XTOPT_TABLEEND,
};

static void DF_help(void)
{
	printf("DF options:\n"
			"  --set  \tset DF bit\n"
			"  --reset\treset DF bit\n");
}

static void DF_parse(struct xt_option_call *cb)
{
	struct xt_df_tginfo *info = (struct xt_df_tginfo *) cb->data;

	xtables_option_parse(cb);
	switch(cb->entry->id) {
		case O_DF_SET:
			info->mode = IPT_DF_SET;
			break;
		case O_DF_RESET:
			info->mode = IPT_DF_RESET;
			break;
		default:
			info->mode = 0;
			printf("invalid parameters\n");
	}
}

static void DF_check(struct xt_fcheck_call *cb)
{
  if (!(cb->xflags & F_ANY))
    xtables_error(PARAMETER_PROBLEM,
        "DF: You must specify an action");
}

static void DF_save(__maybe_unused const void *ip, const struct xt_entry_target *target)
{
	const struct xt_df_tginfo *info = (struct xt_df_tginfo *) target->data;

	switch (info->mode)
	{
		case IPT_DF_SET:
			printf(" --set");
			break;
		case IPT_DF_RESET:
			printf(" --reset");
			break;
	}
}

static void DF_print(__maybe_unused const void *ip, const struct xt_entry_target *target, __maybe_unused int numeric)
{
	const struct xt_df_tginfo *info = (struct xt_df_tginfo *) target->data;

	printf(" DF ");
	switch (info->mode)
	{
		case IPT_DF_SET:
			printf("set");
			break;
		case IPT_DF_RESET:
			printf("reset");
			break;
	}
}

static struct xtables_target df_tg_reg = {
	.name          = "DF",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct xt_df_tginfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_df_tginfo)),
	.help          = DF_help,
	.print         = DF_print,
	.save          = DF_save,
	.x6_parse      = DF_parse,
	.x6_fcheck     = DF_check,
	.x6_options    = DF_opts,
};

void _init(void)
{
	xtables_register_target(&df_tg_reg);
}
