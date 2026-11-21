#ifndef QUOTA_H
#define QUOTA_H

#include "json.h"
#include <stdbool.h>

jval_t *quota_collect(void);
void quota_cache_absorb(const jval_t *res);
int atop_main(int argc, char **argv, const char *sock_path, bool force_direct, bool once);

#endif
