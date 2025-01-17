#include <stdint.h>

typedef struct _IPListCheckNode_t {
    uint32_t node_id;
    uint8_t ip_type;
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    };
    struct _IPListCheckNode_t *next;
} IPListCheckNode_t;

typedef struct _IPListChecker_t IPListChecker_t;

int IPListCheckerCheck(IPListChecker_t *checker, uint8_t *ip, uint8_t ip_type)
{
    if (!checker || !ip)
        return 0;
    
}