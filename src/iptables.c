
/* iptables.c */

#include <stdio.h>
#include <stdlib.h>

int flush_chain(const char *table, const char *chain) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -F %s", table, chain);
    retcode = system(cmd);

    return retcode;
}

int add_mac_rule_to_chain(const char *table, const char *chain, const char *mac, const char *policy) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -A %s -m mac --mac-source \"%s\" -j %s", table, chain, mac, policy);
    retcode = system(cmd);

    return retcode;
}

int check_chain_rule(const char *table, const char *chain, const char *str) {
    char cmd[255];
    int retcode;

    snprintf(cmd, sizeof cmd, "iptables -t %s -nvL %s | grep %s > /dev/null 2>&1", table, chain, str);
    retcode = system(cmd);

    return retcode;
}

int read_chain_bytes(const char *table, const char *chain, const char *str, char *data) {
    char cmd[255];
    char pres[64] = "";
    int retcode = -1;
    FILE *fp;

    /* retrieve the chain bytes */
    snprintf(cmd,
            sizeof cmd, "iptables -t %s -nxvL %s | grep %s | awk '{ print $2 }' 2> /dev/null",
            table,
            chain,
            str);

    fp = popen(cmd, "r");

    if (fp) {
        fgets(pres, sizeof(pres)-1, fp);
        retcode = pclose(fp);

        if (retcode == 0) {
            strcpy(data, pres);
        }
    }

    return retcode;
}

int remove_rule_from_chain(const char *table, const char * chain, const char* str) {
    char cmd[255];
    char pres[64] = "";
    int retcode = -1;
    FILE *fp;

    /* search the rule to delete */
    snprintf(cmd,
            sizeof cmd, "iptables -t %s -nvL %s --line-numbers | grep %s | tail -n 1 | awk '{ print $1 }'",
            table,
            chain,
            str);

    fp = popen(cmd, "r");

    if (fp) {
        fgets(pres, sizeof(pres)-1, fp);
        retcode = pclose(fp);

        if (retcode == 0) {
            /* rule found, delete it */
            snprintf(cmd, sizeof cmd, "iptables -t %s -D %s %s", table, chain, pres);
            retcode = system(cmd);
        }
    }

    return retcode;
}
