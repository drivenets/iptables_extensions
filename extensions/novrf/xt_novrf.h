
#ifndef XT_NOVRF_H_
#define XT_NOVRF_H_

/**
 * XT_NOVRF_IN_DEV     : "--input"
 * XT_NOVRF_OUT_DEV    : "--output"
 * XT_NOVRF_IN_DEV_INV : "! --input"
 *                         Always comes with XT_NOVRF_IN_DEV set.
 * XT_NOVRF_OUT_DEV_INV: "! --output"
 *                         Always comes with XT_NOVRF_OUT_DEV set.
 */
enum {
    XT_NOVRF_IN_DEV      = 1 << 0,
    XT_NOVRF_OUT_DEV     = 1 << 1,
    XT_NOVRF_IN_DEV_INV  = 1 << 2,
    XT_NOVRF_OUT_DEV_INV = 1 << 3,
};

struct xt_novrf_mtinfo {
    unsigned int mode_flags;
};

#endif /** XT_NOVRF_H_ */
