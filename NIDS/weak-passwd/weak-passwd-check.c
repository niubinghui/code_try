#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "weak-passwd-check.h"

const char *weak_passwd[] = 
{
    "123456",
    "12345678",
    NULL
};

static uint32_t WeakPasswdHashFunction(const char * passwd, uint8_t passwd_len, uint32_t hash_table_size)
{
    uint32_t hash = 0;
    uint8_t passwd_index = 0;
    while (passwd_index < passwd_len && passwd[passwd_index]) {
        hash += passwd[passwd_index];
        passwd_index++;
    }
    if (!hash_table_size)
        return hash;
    return hash % hash_table_size;
}

#define G_MAX_HASH_TABLE_SIZE 100000

#define WEAKPASSWDCHECKER_CONTAINS_AT_LEAST_TYPES 3
#define WEAKPASSWDCHECKER_HASH_TABLE_SIZE 200

typedef struct _WeakPasswdHashNode_t {
    char * key_passed;
    struct _WeakPasswdHashNode_t * next;
} WeakPasswdHashNode_t;

typedef struct _WeakPasswdChecker_t {
    uint8_t contains_at_least_types;
    uint32_t hash_table_size;
    WeakPasswdHashNode_t ** hash_table;
} WeakPasswdChecker_t;

static int WeakPasswdCheckerHashTableCreate(WeakPasswdChecker_t * checker);
static void WeakPasswdCheckerHashTableDelete(WeakPasswdChecker_t * checker);
static int WeakPasswdCheckerHashTableInsert(WeakPasswdChecker_t * checker, const char * passwd, uint8_t passwd_len);
static int WeakPasswdCheckerHashTableFind(WeakPasswdChecker_t * checker, char * passwd, uint8_t passwd_len);

static int WeakPasswdCheckerHashTableCreate(WeakPasswdChecker_t * checker)
{
    if (!checker)
        return -1;
    if (checker->hash_table)
        WeakPasswdCheckerHashTableDelete(checker);
    checker->hash_table = (WeakPasswdHashNode_t **)calloc(checker->hash_table_size, sizeof(WeakPasswdHashNode_t *));
    if (!checker->hash_table)
        return -2;
    memset(checker->hash_table, 0, sizeof(WeakPasswdHashNode_t *) * checker->hash_table_size);
    return 0;
}

static void WeakPasswdCheckerHashTableDelete(WeakPasswdChecker_t * checker)
{
    if (!checker || !checker->hash_table)
        return;
    for (uint32_t table_index = 0; table_index < checker->hash_table_size; ++table_index) {
        WeakPasswdHashNode_t * node = checker->hash_table[table_index];
        while (node) {
            WeakPasswdHashNode_t * next_node = node->next;
            free(node->key_passed);
            free(node);
            node = next_node;
        }
    }
    free(checker->hash_table);
    checker->hash_table = NULL;
    return;
}

static int WeakPasswdCheckerHashTableInsert(WeakPasswdChecker_t * checker, const char * passwd, uint8_t passwd_len)
{
    if (WeakPasswdCheckerHashTableFind(checker, passwd, passwd_len))
        // already exist
        return 1;
    
    uint32_t hash = WeakPasswdHashFunction(passwd, passwd_len, checker->hash_table_size);
    WeakPasswdHashNode_t * new_node = (WeakPasswdHashNode_t *)calloc(1, sizeof(WeakPasswdHashNode_t));
    if (!new_node)
        return -1;
    new_node->key_passed = (char *)calloc(1, passwd_len + 1);
    if (!new_node->key_passed) {
        free(new_node);
        return -1;
    }
    memcpy(new_node->key_passed, passwd, passwd_len);
    new_node->key_passed[passwd_len] = '\0';
    new_node->next = checker->hash_table[hash];
    checker->hash_table[hash] = new_node;

    return 0;
}

static int WeakPasswdCheckerHashTableFind(WeakPasswdChecker_t * checker, char * passwd, uint8_t passwd_len)
{
    uint32_t hash = WeakPasswdHashFunction(passwd, passwd_len, checker->hash_table_size);
    WeakPasswdHashNode_t * node = checker->hash_table[hash];
    while (node) {
        if (strcmp(node->key_passed, passwd) == 0)
            return 1;
        node = node->next;
    }
    return 0;
}

#define WEAK_PASSWD_TYPE_LOWER_CHARACTOR 0x01
#define WEAK_PASSWD_TYPE_UPPER_CHARACTOR 0x02
#define WEAK_PASSWD_TYPE_NUMBER 0x04
#define WEAK_PASSWD_TYPE_SPECIAL_CHARACTOR 0x08

WeakPasswdChecker_t *WeakPasswdCheckerNew(uint8_t contains_at_least_types, uint32_t hash_table_size)
{
    if (contains_at_least_types > 4 || contains_at_least_types < 1)
        return NULL;
    if (hash_table_size < 1 || hash_table_size > G_MAX_HASH_TABLE_SIZE)
        return NULL;
    WeakPasswdChecker_t *new_checker = (WeakPasswdChecker_t *)calloc(1, sizeof(WeakPasswdChecker_t));
    if (!new_checker)
        return NULL;
    new_checker->contains_at_least_types = contains_at_least_types;
    new_checker->hash_table_size = hash_table_size;
    WeakPasswdCheckerHashTableNew(new_checker);
    return new_checker;
}

void WeakPasswdCheckerFree(WeakPasswdChecker_t *checker)
{

    return;
}

int WeakPasswdCheckerLoad(WeakPasswdChecker_t *checker, const char *passwd_file)
{
    return 0;
}

int WeakPasswdCheckerLoadFromMemory(WeakPasswdChecker_t *checker, const char **passwd_data, uint32_t passwd_data_num)
{
    return 0;
}

int WeakPasswdCheckerCheck(WeakPasswdChecker_t *checker, const char *passwd, uint8_t passwd_len, uint8_t *weak_type)
{
    uint8_t passwd_alphabet_types = 0x00;
    char * passwd_p = (char *)passwd;
    uint8_t passwd_index = 0;

    while (passwd_index < passwd_len) {
        if (passwd_p[passwd_index] >= 'a' && passwd_p[passwd_index] <= 'z') {
            passwd_alphabet_types |= WEAK_PASSWD_TYPE_LOWER_CHARACTOR;
        } else if (passwd_p[passwd_index] >= 'A' && passwd_p[passwd_index] <= 'Z') {
            passwd_alphabet_types |= WEAK_PASSWD_TYPE_UPPER_CHARACTOR;
        } else if (passwd_p[passwd_index] >= '0' && passwd_p[passwd_index] <= '9') {
            passwd_alphabet_types |= WEAK_PASSWD_TYPE_NUMBER;
        } else {
            passwd_alphabet_types |= WEAK_PASSWD_TYPE_SPECIAL_CHARACTOR;
        }
    }
    return 0;
}