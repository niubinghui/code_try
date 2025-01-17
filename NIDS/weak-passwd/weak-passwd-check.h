#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

typedef struct _WeakPasswdChecker_t WeakPasswdChecker_t;

#define WEAK_PASSWD_TYPE_NONE 0
#define WEAK_PASSWD_TYPE_AT_LEAST_TYPE 1
#define WEAK_PASSWD_TYPE_HASH 2

WeakPasswdChecker_t *WeakPasswdCheckerNew(uint8_t contains_at_least_types, uint32_t hash_table_size);
void WeakPasswdCheckerFree(WeakPasswdChecker_t *checker);
int WeakPasswdCheckerLoad(WeakPasswdChecker_t *checker, const char *passwd_file);
int WeakPasswdCheckerLoadFromMemory(WeakPasswdChecker_t *checker, const char **passwd_data, uint32_t passwd_data_num);
int WeakPasswdCheckerCheck(WeakPasswdChecker_t *checker, const char *passwd, uint8_t passwd_len, uint8_t *weak_type);

#ifdef __cplusplus
}
#endif