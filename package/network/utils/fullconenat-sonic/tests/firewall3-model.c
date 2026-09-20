#include <assert.h>
#include <stdio.h>
#include "options.h"
#include "iptables.h"

struct fw3_ipt_rule {
    unsigned int proto;
    struct fw3_address *src, *dest;
    char target[64], chain[64], ports[32];
};
static struct fw3_ipt_rule rules[256];
static int nrules, cases;
const char *fw3_flag_names[__FW3_FLAG_MAX] = {[FW3_FLAG_ACCEPT] = "ACCEPT"};
void info(const char *fmt, ...) {}
void fw3_ipt_rule_extra(struct fw3_ipt_rule *r, const char *s) {}
void fw3_ipt_rule_comment(struct fw3_ipt_rule *r, const char *s, ...) {}
static void print_interface_rules(struct fw3_ipt_handle *h, struct fw3_state *s, bool reload, struct fw3_zone *z) {}
void fw3_print_cthelpers(struct fw3_ipt_handle *h, struct fw3_state *s, struct fw3_zone *z) {}
struct fw3_ipt_rule *fw3_ipt_rule_new(struct fw3_ipt_handle *h) {
    assert(nrules < 256); return &rules[nrules++];
}
void fw3_ipt_rule_proto(struct fw3_ipt_rule *r, struct fw3_protocol *p) {r->proto = p->protocol;}
void fw3_ipt_rule_src_dest(struct fw3_ipt_rule *r, struct fw3_address *s, struct fw3_address *d) {r->src=s; r->dest=d;}
void fw3_ipt_rule_addarg(struct fw3_ipt_rule *r, bool inv, const char *k, const char *v) {
    assert(!inv);
    if (!strcmp(k,"-j")) snprintf(r->target,sizeof(r->target),"%s",v);
    else if (!strcmp(k,"--to-ports")) snprintf(r->ports,sizeof(r->ports),"%s",v);
    else assert(0);
}
void __fw3_ipt_rule_append(struct fw3_ipt_rule *r, bool repl, const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vsnprintf(r->chain,sizeof(r->chain),fmt,ap); va_end(ap);
}

/* Actual patched source, extracted without altering the rendering functions. */
#include "fw3-zone-render.inc"

static struct fw3_state state;
static struct fw3_zone zone;
static struct fw3_ipt_handle handle;
static struct fw3_protocol protos[8];
static struct fw3_address srcs[4], dests[4];
static void reset(void) {
    memset(&state,0,sizeof(state)); memset(&zone,0,sizeof(zone));
    memset(rules,0,sizeof(rules)); memset(protos,0,sizeof(protos));
    memset(srcs,0,sizeof(srcs)); memset(dests,0,sizeof(dests)); nrules=0;
    INIT_LIST_HEAD(&zone.masq_src); INIT_LIST_HEAD(&zone.masq_dest);
    state.defaults.fullcone=true; zone.fullcone=true; zone.masq=true; zone.name="wan";
    handle.family=FW3_FAMILY_V4; handle.table=FW3_TABLE_NAT;
}
static void address(struct fw3_address *a, struct list_head *head, bool invert) {
    a->set=true; a->invert=invert; a->family=FW3_FAMILY_V4;
    list_add_tail(&a->list,head);
}
static void check(int post, int pre, int masq, int ret, unsigned int only_proto) {
    print_zone_rule(&handle,&state,false,&zone);
    int npost=0,npre=0,nmasq=0,nret=0;
    for (int i=0;i<nrules;i++) {
        struct fw3_ipt_rule *r=&rules[i];
        if (!strcmp(r->target,"FULLCONE")) {
            assert(r->proto==IPPROTO_TCP || r->proto==IPPROTO_UDP || r->proto==IPPROTO_UDPLITE || r->proto==IPPROTO_SCTP);
            if (!strcmp(r->chain,"zone_wan_postrouting")) {
                assert(!strcmp(r->ports,"1024-65535")); npost++;
            } else {
                assert(!strcmp(r->chain,"zone_wan_prerouting"));
                assert(!r->ports[0] && !r->src && !r->dest); npre++;
            }
        } else if (!strcmp(r->target,"MASQUERADE")) { assert(!r->ports[0]); nmasq++; }
        else if (!strcmp(r->target,"RETURN")) {assert(npost==0 && nmasq==0); nret++;}
        else assert(0);
    }
    assert(npost==post && npre==pre && nmasq==masq && nret==ret); cases++;
}
int main(void) {
    reset(); check(4,4,1,0,0);
    reset(); state.defaults.fullcone=false; check(0,0,1,0,0);
    reset(); zone.fullcone=false; check(0,0,1,0,0);
    reset(); zone.masq=false; check(0,0,0,0,0);
    reset(); handle.family=FW3_FAMILY_V6; check(0,0,0,0,0);
    reset(); zone.family=FW3_FAMILY_V6; check(0,0,0,0,0);
    reset();
    for(int i=0;i<3;i++) {
        address(&srcs[i],&zone.masq_src,i==2);
        address(&dests[i],&zone.masq_dest,i==2);
    }
    check(16,4,4,2,0);
    for (int i=2;i<nrules-4;i++) {
        assert(rules[i].src==&srcs[(i-2)/10]);
        assert(rules[i].dest==&dests[((i-2)/5)%2]);
        assert(!strcmp(rules[i].target,(i-2)%5==4 ? "MASQUERADE" : "FULLCONE"));
    }
    assert(srcs[2].invert && dests[2].invert);
    printf("PASS %d fw3 fixed-protocol rule-rendering cases\n",cases);
}