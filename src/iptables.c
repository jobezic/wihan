
/* iptables.c */

#include <stdio.h>
#include <stdlib.h>

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
