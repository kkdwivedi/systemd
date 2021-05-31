/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */

#include <linux/if_ether.h>
#include <linux/pkt_sched.h>
#include <math.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "parse-util.h"
#include "percent-util.h"
#include "string-util.h"
#include "tc-util.h"
#include "time-util.h"

int tc_init(double *ret_ticks_in_usec, uint32_t *ret_hz) {
        static double ticks_in_usec = -1;
        static uint32_t hz;

        if (ticks_in_usec < 0) {
                uint32_t clock_resolution, ticks_to_usec, usec_to_ticks;
                _cleanup_free_ char *line = NULL;
                double clock_factor;
                int r;

                r = read_one_line_file("/proc/net/psched", &line);
                if (r < 0)
                        return r;

                r = sscanf(line, "%08x%08x%08x%08x", &ticks_to_usec, &usec_to_ticks, &clock_resolution, &hz);
                if (r < 4)
                        return -EIO;

                clock_factor = (double) clock_resolution / USEC_PER_SEC;
                ticks_in_usec = (double) ticks_to_usec / usec_to_ticks * clock_factor;
        }

        if (ret_ticks_in_usec)
                *ret_ticks_in_usec = ticks_in_usec;
        if (ret_hz)
                *ret_hz = hz;

        return 0;
}

int tc_time_to_tick(usec_t t, uint32_t *ret) {
        double ticks_in_usec;
        usec_t a;
        int r;

        assert(ret);

        r = tc_init(&ticks_in_usec, NULL);
        if (r < 0)
                return r;

        a = t * ticks_in_usec;
        if (a > UINT32_MAX)
                return -ERANGE;

        *ret = a;
        return 0;
}

int parse_tc_percent(const char *s, uint32_t *ret_fraction) {
        int r;

        assert(s);
        assert(ret_fraction);

        r = parse_permyriad(s);
        if (r < 0)
                return r;

        *ret_fraction = (double) r / 10000 * UINT32_MAX;
        return 0;
}

int tc_transmit_time(uint64_t rate, uint32_t size, uint32_t *ret) {
        return tc_time_to_tick(USEC_PER_SEC * ((double)size / (double)rate), ret);
}

int tc_fill_ratespec_and_table(struct tc_ratespec *rate, uint32_t *rtab, uint32_t mtu) {
        uint32_t cell_log = 0;
        int r;

        if (mtu == 0)
                mtu = 2047;

        while ((mtu >> cell_log) > 255)
                cell_log++;

        for (size_t i = 0; i < 256; i++) {
                uint32_t sz;

                sz = (i + 1) << cell_log;
                if (sz < rate->mpu)
                        sz = rate->mpu;
                r = tc_transmit_time(rate->rate, sz, &rtab[i]);
                if (r < 0)
                        return r;
        }

        rate->cell_align = -1;
        rate->cell_log = cell_log;
        rate->linklayer = TC_LINKLAYER_ETHERNET;
        return 0;
}

int parse_handle(const char *t, uint32_t *ret) {
        _cleanup_free_ char *word = NULL;
        uint16_t major, minor;
        int r;

        assert(t);
        assert(ret);

        /* Extract the major number. */
        r = extract_first_word(&t, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;
        if (!t)
                return -EINVAL;

        r = safe_atou16_full(word, 16, &major);
        if (r < 0)
                return r;

        r = safe_atou16_full(t, 16, &minor);
        if (r < 0)
                return r;

        *ret = ((uint32_t) major << 16) | minor;
        return 0;
}

#define X(p, n) { ETH_P_##p, #n }
static const struct {
        int id;
        const char *name;
} proto_name_to_id[] = {
        /* start with most common three options */
        X(ALL, all),
        X(IP, ip),
        X(IP, ipv4),
        X(LOOP, loop),
        X(PUP, pup),
        X(PUPAT, pupat),
        X(X25, x25),
        X(ARP, arp),
        X(BPQ, bpq),
        X(IEEEPUP, ieeepup),
        X(IEEEPUPAT, ieeepupat),
        X(DEC, dec),
        X(DNA_DL, dna_dl),
        X(DNA_RC, dna_rc),
        X(DNA_RT, dna_rt),
        X(LAT, lat),
        X(DIAG, diag),
        X(CUST, cust),
        X(SCA, sca),
        X(RARP, rarp),
        X(ATALK, atalk),
        X(AARP, aarp),
        X(IPX, ipx),
        X(IPV6, ipv6),
        X(PPP_DISC, ppp_disc),
        X(PPP_SES, ppp_ses),
        X(ATMMPOA, atmmpoa),
        X(ATMFATE, atmfate),
        X(802_3, 802_3),
        X(AX25, ax25),
        X(802_2, 802_2),
        X(SNAP, snap),
        X(DDCMP, ddcmp),
        X(WAN_PPP, wan_ppp),
        X(PPP_MP, ppp_mp),
        X(LOCALTALK, localtalk),
        X(CAN, can),
        X(PPPTALK, ppptalk),
        X(TR_802_2, tr_802_2),
        X(MOBITEX, mobitex),
        X(CONTROL, control),
        X(IRDA, irda),
        X(ECONET, econet),
        X(TIPC, tipc),
        X(AOE, aoe),
        X(8021Q, 802.1Q),
        X(8021AD, 802.1ad),
        X(MPLS_UC, mpls_uc),
        X(MPLS_MC, mpls_mc),
        X(TEB, teb),
        { 0x8100, "802.1Q" },
        { 0x88cc, "LLDP" },
};
#undef X

int parse_protocol(const char *t, uint16_t *ret) {
        for (int i = 0; i < ELEMENTSOF(proto_name_to_id); i++) {
                if (streq(proto_name_to_id[i].name, t)) {
                        *ret = proto_name_to_id[i].id;
                        return 0;
                }
        }

        return -ENOENT;
}

/* copied from tc/tc_estimator.c GPL-2.0 */
int parse_estimator(unsigned int interval, unsigned int time_const, struct tc_estimator *est) {
        for (est->interval = 0; est->interval <= 5; est->interval++) {
                if (interval <= (1 << est->interval) * (USEC_PER_SEC / 4))
                        break;
        }

        if (est->interval > 5)
                return -EINVAL;

        est->interval -= 2;
        for (est->ewma_log = 1; est->ewma_log < 32; est->ewma_log++) {
                double w = 1.0 - 1.0 / (1 << est->ewma_log);

                if (interval / (-log(w)) > time_const)
                        break;
        }

        est->ewma_log--;
        if (est->ewma_log == 0 || est->ewma_log >= 31)
                return -EINVAL;

        return 0;
}
