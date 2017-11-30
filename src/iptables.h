
/* iptables.h */

int remove_rule_from_chain(const char *, const char *, const char *);
int read_chain_bytes(const char *, const char *, const char *, char *);
int check_chain_rule(const char *, const char *, const char *);
int add_mac_rule_to_chain(const char *, const char *, const char *, const char *);
int flush_chain(const char *, const char *);
