#ifndef IPT_DF_H
#define IPT_DF_H

typedef enum {
	IPT_DF_SET = 1,
	IPT_DF_RESET,
} df_mode;

struct xt_df_tginfo {
	df_mode mode;
};

#endif /* IPT_DF_H */
