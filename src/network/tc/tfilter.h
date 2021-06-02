// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "tc.h"
#include "time-util.h"

typedef enum TFilterKind {
        TFILTER_KIND_BPF,
        TFILTER_KIND_FLOW,
        TFILTER_KIND_FLOWER,
        TFILTER_KIND_FW,
        TFILTER_KIND_U32,
        _TFILTER_KIND_MAX,
        _TFILTER_KIND_INVALID = -EINVAL,
} TFilterKind;

typedef struct TFilter {
        TrafficControl meta;

        NetworkConfigSection *section;
        Network *network;

        uint32_t parent;
        uint32_t handle;
        uint32_t chain;
        uint16_t priority;
        uint16_t protocol;
        uint32_t classid;
        usec_t est_interval;
        usec_t est_time_const;

        TFilterKind kind;
} TFilter;

typedef struct TFilterVTable {
        size_t object_size;
        const char *tca_kind;
        int (*init)(TFilter *tfilter);
        int (*fill_message)(Link *link, TFilter *tfilter, sd_netlink_message *m);
        int (*verify)(TFilter *tfilter);
        void (*destroy)(TFilter *tfilter);
} TFilterVTable;

extern const TFilterVTable * const tfilter_vtable[_TFILTER_KIND_MAX];

#define TFILTER_VTABLE(t) ((t)->kind != _TFILTER_KIND_INVALID ? tfilter_vtable[(t)->kind] : NULL)

#define DEFINE_TFILTER_CAST(UPPERCASE, MixedCase)                               \
        static inline MixedCase* TFILTER_TO_##UPPERCASE(TFilter *t) {           \
                if (_unlikely_(!t || t->kind != TFILTER_KIND_##UPPERCASE))      \
                        return NULL;                                            \
                                                                                \
                return (MixedCase*) t;                                          \
        }

#define TFILTER(t) (&(t)->meta)

TFilter* tfilter_free(TFilter *tfilter);
int tfilter_new_static(TFilterKind kind, Network *network, const char *filename, unsigned section_line, TFilter **ret);

int tfilter_configure(Link *link, TFilter *tfilter);
int tfilter_section_verify(TFilter *tfilter);

DEFINE_NETWORK_SECTION_FUNCTIONS(TFilter, tfilter_free);

DEFINE_TC_CAST(FILTER, TFilter);

CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_parent);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_handle);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_chain);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_classid);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_est_interval);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_est_time_const);

#include "fbpf.h"
#include "ffw.h"
