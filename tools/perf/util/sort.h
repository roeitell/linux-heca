#ifndef __PERF_SORT_H
#define __PERF_SORT_H
#include "../builtin.h"

#include "util.h"

#include "color.h"
#include <linux/list.h>
#include "cache.h"
#include <linux/rbtree.h>
#include "symbol.h"
#include "string.h"
#include "callchain.h"
#include "strlist.h"
#include "values.h"

#include "../perf.h"
#include "debug.h"
#include "header.h"

#include "parse-options.h"
#include "parse-events.h"

#include "thread.h"
#include "sort.h"

extern regex_t parent_regex;
extern const char *sort_order;
extern const char default_parent_pattern[];
extern const char *parent_pattern;
extern const char default_sort_order[];
extern int sort__need_collapse;
extern int sort__has_parent;
extern int sort__has_sym;
extern int sort__branch_mode;
extern struct sort_entry sort_comm;
extern struct sort_entry sort_dso;
extern struct sort_entry sort_sym;
extern struct sort_entry sort_parent;
extern struct sort_entry sort_dso_from;
extern struct sort_entry sort_dso_to;
extern struct sort_entry sort_sym_from;
extern struct sort_entry sort_sym_to;
extern enum sort_type sort__first_dimension;

struct he_stat {
	u64			period;
	u64			period_sys;
	u64			period_us;
	u64			period_guest_sys;
	u64			period_guest_us;
	u32			nr_events;
};

struct hist_entry_diff {
	bool	computed;

	/* PERF_HPP__DELTA */
	double	period_ratio_delta;

	/* PERF_HPP__RATIO */
	double	period_ratio;

	/* HISTC_WEIGHTED_DIFF */
	s64	wdiff;
};

/**
 * struct hist_entry - histogram entry
 *
 * @row_offset - offset from the first callchain expanded to appear on screen
 * @nr_rows - rows expanded in callchain, recalculated on folding/unfolding
 */
struct hist_entry {
	struct rb_node		rb_node_in;
	struct rb_node		rb_node;
	union {
		struct list_head node;
		struct list_head head;
	} pairs;
	struct he_stat		stat;
	struct map_symbol	ms;
	struct thread		*thread;
	u64			ip;
	s32			cpu;

	struct hist_entry_diff	diff;

	/* XXX These two should move to some tree widget lib */
	u16			row_offset;
	u16			nr_rows;

	bool			init_have_children;
	char			level;
	bool			used;
	u8			filtered;
	char			*srcline;
	struct symbol		*parent;
	unsigned long		position;
	struct rb_root		sorted_chain;
	struct branch_info	*branch_info;
	struct hists		*hists;
	struct callchain_root	callchain[0];
};

static inline bool hist_entry__has_pairs(struct hist_entry *he)
{
	return !list_empty(&he->pairs.node);
}

static inline struct hist_entry *hist_entry__next_pair(struct hist_entry *he)
{
	if (hist_entry__has_pairs(he))
		return list_entry(he->pairs.node.next, struct hist_entry, pairs.node);
	return NULL;
}

static inline void hist_entry__add_pair(struct hist_entry *he,
					struct hist_entry *pair)
{
	list_add_tail(&he->pairs.head, &pair->pairs.node);
}

enum sort_type {
	/* common sort keys */
	SORT_PID,
	SORT_COMM,
	SORT_DSO,
	SORT_SYM,
	SORT_PARENT,
	SORT_CPU,
	SORT_SRCLINE,

	/* branch stack specific sort keys */
	__SORT_BRANCH_STACK,
	SORT_DSO_FROM = __SORT_BRANCH_STACK,
	SORT_DSO_TO,
	SORT_SYM_FROM,
	SORT_SYM_TO,
	SORT_MISPREDICT,
};

/*
 * configurable sorting bits
 */

struct sort_entry {
	struct list_head list;

	const char *se_header;

	int64_t (*se_cmp)(struct hist_entry *, struct hist_entry *);
	int64_t (*se_collapse)(struct hist_entry *, struct hist_entry *);
	int	(*se_snprintf)(struct hist_entry *self, char *bf, size_t size,
			       unsigned int width);
	u8	se_width_idx;
	bool	elide;
};

extern struct sort_entry sort_thread;
extern struct list_head hist_entry__sort_list;

int setup_sorting(void);
extern int sort_dimension__add(const char *);
void sort_entry__setup_elide(struct sort_entry *self, struct strlist *list,
			     const char *list_name, FILE *fp);

#endif	/* __PERF_SORT_H */
