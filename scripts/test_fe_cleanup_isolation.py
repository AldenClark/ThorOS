#!/usr/bin/env python3
"""Execute the production cleanup worker with bounded retries and fault rotation.

The companion flow-release test executes real MMIO ownership release; this
oracle controls only completion/failure and verifies scheduling/lock scope.
"""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
native = (root / 'port/overlay/target/linux/rtl9617c/files-6.18/drivers/net/ethernet/realtek/rtl9617c-fe.c').read_text()

def function(name):
    start = re.search(r'^static void ' + name + r'\(', native, re.M).start()
    end = native.index('{', start) + 1
    depth = 1
    while depth:
        depth += (native[end] == '{') - (native[end] == '}')
        end += 1
    return native[start:end]

fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define HZ 100U
#define system_wq 0
#define min(a,b) ((a)<(b)?(a):(b))
struct list_head {struct list_head *next,*prev;};
static void init(struct list_head *h){h->next=h->prev=h;}
static bool list_empty(struct list_head *h){return h->next==h;}
static void list_del(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;}
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_move_tail(struct list_head *n,struct list_head *h){list_del(n);list_add_tail(n,h);}
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry(p,h,m) for(struct list_head *c=(h)->next;c!=(h) && ((p)=container_of(c,__typeof__(*(p)),m));c=c->next)
struct work_struct {unsigned unused;};
struct delayed_work {struct work_struct work;unsigned queued,delay;};
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
struct rtl_fe_flow {struct list_head retry;bool fails,released,withdrawal_pending,resource_fails;unsigned attempts;};
struct rtl_fe {struct delayed_work cleanup_work;struct list_head retries;
 bool shutting_down;unsigned lock,cleanup_delay,collects,releases,pending_withdrawals;};
static void mutex_lock(unsigned *l){assert(!*l);*l=1;}
static void mutex_unlock(unsigned *l){assert(*l);*l=0;}
static void mod_delayed_work(unsigned queue,struct delayed_work *w,unsigned delay){assert(!queue);assert(delay>=HZ && delay<=32*HZ);w->queued++;w->delay=delay;}
static int fe_delete(struct rtl_fe *fe,struct rtl_fe_flow *f){
 assert(fe->lock && !f->released);f->attempts++;
 if(f->fails)return -ETIMEDOUT;
 if(f->withdrawal_pending){assert(fe->pending_withdrawals);fe->pending_withdrawals--;f->withdrawal_pending=false;}
 if(f->resource_fails)return -ETIMEDOUT;
 list_del(&f->retry);init(&f->retry);f->released=true;fe->releases++;return 0;
}
static void fe_collect_ports(struct rtl_fe *fe){assert(fe->lock);fe->collects++;}
'''
tests = r'''
static void withdrawal_progress_budget(void){
 struct rtl_fe fe={0};struct rtl_fe_flow flow[20]={0};init(&fe.retries);
 for(unsigned int i=0;i<20;i++){
  init(&flow[i].retry);list_add_tail(&flow[i].retry,&fe.retries);
  flow[i].withdrawal_pending=flow[i].resource_fails=true;
 }
 fe.pending_withdrawals=20;fe.cleanup_delay=32*HZ;
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.pending_withdrawals==12 && !fe.releases && fe.cleanup_delay==HZ);
 for(unsigned int i=0;i<20;i++)assert(flow[i].attempts==(i<8));
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.pending_withdrawals==4 && !fe.releases && fe.cleanup_delay==HZ);
 for(unsigned int i=0;i<20;i++)assert(flow[i].attempts==(i<16));
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(!fe.pending_withdrawals && !fe.releases && fe.cleanup_delay==2*HZ);
 for(unsigned int i=0;i<20;i++)assert(flow[i].attempts==1);
 /* After the publication gate clears, ordinary resource-only failure
  * still ends a batch; partial progress cannot turn into a busy loop. */
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(flow[0].attempts==2 && fe.cleanup_delay==4*HZ);
 for(unsigned int i=0;i<20;i++)flow[i].resource_fails=false;
 for(unsigned int i=0;i<3;i++)fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==20 && list_empty(&fe.retries) && !fe.cleanup_delay);
}
static void withdrawal_priority(void){
 struct rtl_fe fe={0};struct rtl_fe_flow flow[3]={0};init(&fe.retries);
 for(unsigned int i=0;i<3;i++){
  init(&flow[i].retry);list_add_tail(&flow[i].retry,&fe.retries);flow[i].fails=true;
 }
 /* A is only restoring an EIF. B/C still own uncertain publications.
  * The first failed resource must not block the route gate's owners. */
 flow[1].withdrawal_pending=flow[2].withdrawal_pending=true;fe.pending_withdrawals=2;
 fe.cleanup_delay=32*HZ;
 for(unsigned int i=0;i<4;i++)fe_cleanup_work(&fe.cleanup_work.work);
 assert(!flow[0].attempts && flow[1].attempts==2 && flow[2].attempts==2);
 assert(!fe.releases && fe.pending_withdrawals==2 && fe.cleanup_delay==32*HZ);
 /* Both failed pending owners get a turn, even with a failing resource
  * owner at the front; a recovered one retires without waiting on A. */
 flow[2].fails=false;
 fe_cleanup_work(&fe.cleanup_work.work); /* B fails, C gets the next turn. */
 fe_cleanup_work(&fe.cleanup_work.work); /* C succeeds; B still fails. */
 assert(flow[2].released && fe.pending_withdrawals==1 && !flow[0].attempts);
 assert(!flow[1].released && !flow[0].released);
 flow[1].fails=false;fe_cleanup_work(&fe.cleanup_work.work);
 assert(flow[1].released && !fe.pending_withdrawals && flow[0].attempts==1);
 assert(!flow[0].released && fe.retries.next==&flow[0].retry);
 flow[0].fails=false;fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==3 && list_empty(&fe.retries) && !fe.cleanup_delay);
}
int main(void){
 withdrawal_priority();
 withdrawal_progress_budget();
 struct rtl_fe fe={0};struct rtl_fe_flow flow[20]={0};init(&fe.retries);
 for(unsigned i=0;i<20;i++){init(&flow[i].retry);list_add_tail(&flow[i].retry,&fe.retries);}
 flow[0].fails=true;
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(flow[0].attempts==1 && !fe.releases && fe.retries.prev==&flow[0].retry);
 assert(fe.cleanup_delay==HZ && fe.cleanup_work.delay==HZ && !fe.lock);
 /* The stuck owner moved to the tail. Each healthy batch is at most8,
  * then drops the global mutex before scheduling the next batch. */
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==8 && flow[0].attempts==1 && !fe.lock);
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==16 && flow[0].attempts==1 && !fe.lock);
 fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==19 && flow[0].attempts==2 && !flow[0].released);
 assert(fe.cleanup_delay==2*HZ && fe.cleanup_work.delay==2*HZ);
 for(unsigned n=0;n<10;n++)fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.cleanup_delay==32*HZ && fe.cleanup_work.delay==32*HZ);
 unsigned attempts=flow[0].attempts,queued=fe.cleanup_work.queued;
 fe.shutting_down=true;fe_cleanup_work(&fe.cleanup_work.work);
 assert(flow[0].attempts==attempts && fe.cleanup_work.queued==queued && !fe.lock);
 fe.shutting_down=false;flow[0].fails=false;fe_cleanup_work(&fe.cleanup_work.work);
 assert(fe.releases==20 && list_empty(&fe.retries) && !fe.cleanup_delay && !fe.lock);
 assert(fe.cleanup_work.queued==queued); /* Empty queue must not self-poll. */
 puts("FE cleanup: independent bounded8 batch, failure rotates,1..32s backoff, retained owner, shutdown/no-empty-poll passed");
 puts("FE cleanup: pending publications precede resource-only failures, rotate fairly and return to the normal queue after withdrawal");
}
'''
with tempfile.TemporaryDirectory(prefix='fe-cleanup-') as name:
    work = Path(name)
    (work / 'test.c').write_text(fixture + function('fe_cleanup_work') + tests)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(work / 'test.c'),
                    '-o', str(work / 'test')], check=True)
    subprocess.run([str(work / 'test')], check=True)

# Admission/statistics callbacks must never drain the global failure list.
callback = native[native.index('static int fe_block_callback('):native.index('static void fe_block_release(')]
assert 'fe->retries' not in callback and 'list_for_each' not in callback
delete = native[native.index('static int fe_delete('):native.index('static void fe_cleanup_work(')]
assert 'queue_delayed_work(' in delete and 'mod_delayed_work(' not in delete
