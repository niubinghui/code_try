#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcidr.h>


// 将 IP 地址字符串转换为无符号整数
unsigned int ip_to_uint(char *ip) {
    unsigned int num = 0;
    unsigned int octet;
    int i;
    char *token;
    token = strtok(ip, ".");
    for (i = 0; i < 4 && token!= NULL; i++) {
        octet = atoi(token);
        num = (num << 8) | octet;
        token = strtok(NULL, ".");
    }
    return num;
}


// 将 CIDR 表示的网络地址和子网掩码转换为无符号整数
void cidr_to_netmask(unsigned int *network, unsigned int *mask, char *cidr) {
    char *slash = strchr(cidr, '/');
    if (slash == NULL) {
        *network = ip_to_uint(cidr);
        *mask = 0xFFFFFFFF;
    } else {
        *network = ip_to_uint(cidr);
        int prefix_length = atoi(slash + 1);
        *mask = 0xFFFFFFFF << (32 - prefix_length);
    }
}


// 检查 IP 地址是否在网段列表中
int check_ip_in_networks(char *ip, char **network_list, int list_size) {
    unsigned int ip_num = ip_to_uint(ip);
    for (int i = 0; i < list_size; i++) {
        unsigned int network, mask;
        cidr_to_netmask(&network, &mask, network_list[i]);
        if ((ip_num & mask) == (network & mask)) {
            return 1;
        }
    }
    return 0;
}


int main() {
    char *network_list[] = {"192.168.1.0/24", "10.0.0.0/8"};
    int list_size = sizeof(network_list) / sizeof(network_list[0]);
    char *test_ip = "192.168.1.10";


    if (check_ip_in_networks(test_ip, network_list, list_size)) {
        printf("%s is in the network list.\n", test_ip);
    } else {
        printf("%s is not in the network list.\n", test_ip);
    }


    return 0;
}