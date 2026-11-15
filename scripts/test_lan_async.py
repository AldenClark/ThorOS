#!/usr/bin/env python3
"""Exercise production LAN registration with real threads and modeled RTNL."""
from pathlib import Path
import resource
import subprocess
import tempfile
from test_lan_probe_isolation import shim, function

# Reuse fault injection, but replace inline work/completions and RTNL with pthreads.
start = shim.index('static struct work_struct *pending_work;')
end = shim.index('struct device_node {', start)
threading = r'''
static pthread_mutex_t rtnl = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static _Thread_local int rtnl_owned;
static _Thread_local int actor;
static pthread_t worker, opener, remover;
static pthread_t external;
static int open_attempt, open_waiting, opened, worker_created, worker_finished;
static int remove_started, remove_passed, remove_mode;
static int early_mode,external_has_rtnl,registration_attempted,external_deferred;
static void rtnl_lock(void){
 if(early_mode && !actor){
  pthread_mutex_lock(&gate);
  if(external_has_rtnl && !registration_attempted){registration_attempted=1;pthread_cond_broadcast(&changed);}
  pthread_mutex_unlock(&gate);
 }
 pthread_mutex_lock(&rtnl);rtnl_owned=1;
}
static void rtnl_unlock(void){assert(rtnl_owned);rtnl_owned=0;pthread_mutex_unlock(&rtnl);}
#define init_completion(c) ((c)->done=0)
static void complete_all(struct completion *c){
 pthread_mutex_lock(&gate);c->done=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
}
static void wait_for_completion(struct completion *c){
 assert(rtnl_owned);
 assert(actor!=1 && "external consumer must defer before LAN registration");
 pthread_mutex_lock(&gate);open_waiting=1;pthread_cond_broadcast(&changed);
 while(!c->done)pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);
}
static void *run_work(void *arg){
 struct work_struct *work=arg;
 pthread_mutex_lock(&gate);
 while(!(remove_mode?remove_started:open_waiting))pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);
 work->func(work);
 pthread_mutex_lock(&gate);worker_finished=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
 return NULL;
}
static bool schedule_work(struct work_struct *work){
 worker_created=1;assert(!pthread_create(&worker,NULL,run_work,work));return true;
}
static void flush_work(struct work_struct *work){(void)work;assert(!pthread_join(worker,NULL));}
'''
code = shim[:start] + threading + shim[end:]
# The shared isolation fixture already declares the current NI lifecycle
# fields. This harness replaces its engine-start boundary, not those fields.
code = code[:code.index('static unsigned int engine_starts;')]
code = code.replace('struct device {struct device_node *of_node;};',
                    'struct device {struct device_node *of_node;int kobj;};')
code = code.replace('int tx_lock,dma;', 'int tx_lock,dma,mib_work;')
start = code.index('static int register_netdevice(')
end = code.index('static void unregister_netdev(', start)
code = code[:start] + 'static int register_netdevice(struct net_device *d);\n' + code[end:]
code += r'''
static unsigned int engine_ports;
static int rtl_engine_start(struct rtl_xram *priv){
 assert(rtnl_owned);
 engine_ports=0;
 for(unsigned int i=0;i<5;i++)if(priv->ports[i])engine_ports|=BIT(i);
 /* No synchronous port may be omitted by the first scheduler/QM setup. */
 assert((engine_ports & (board_ports==5?7:15))==(board_ports==5?7:15));
 if(board_ports==5 && stage>=1 && stage<=7)assert(!(engine_ports&BIT(4)));
 return 0;
}
'''
code += function('rtl_engine_get')
code += r'''
static void *open_external(void *arg){
 actor=1;rtnl_lock();
 pthread_mutex_lock(&gate);external_has_rtnl=1;pthread_cond_broadcast(&changed);
 while(!registration_attempted)pthread_cond_wait(&changed,&gate);
 pthread_mutex_unlock(&gate);
 /* NI drvdata can be visible to a PON supplier consumer before LAN
  * registration starts. It must not wait for unqueued NI4 work under RTNL. */
 assert(rtl_engine_get(arg)==-EPROBE_DEFER);external_deferred=1;
 rtnl_unlock();return NULL;
}
static void *open_first(void *arg){
 pthread_mutex_lock(&gate);open_attempt=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
 rtnl_lock();assert(!rtl_engine_get(arg));opened=1;rtnl_unlock();return NULL;
}
static int register_netdevice(struct net_device *d){
 assert(rtnl_owned);
 assert(d->dev_port==d->lan.port);
 if(stage==8 && d->lan.port==4)return -EIO;
 assert(d->phydev);active|=BIT(d->lan.port);
 if(d->lan.port==0){
  pthread_mutex_lock(&gate);
  assert(!pthread_create(&opener,NULL,open_first,d->lan.shared));
  while(!open_attempt)pthread_cond_wait(&changed,&gate);
  pthread_mutex_unlock(&gate);
 }
 return 0;
}
'''
code += '\n'.join(function(n) for n in ('rtl_unregister_lan', 'rtl_sgmii_power_off',
                                       'rtl_lan_number', 'rtl_register_lan', 'rtl_lan4_work', 'rtl_register_lans'))
code += r'''
static const int rtl_native_groups[1];
static int sysfs_create_groups(int *kobj,const int *groups){(void)kobj;(void)groups;return 0;}
#define HZ 100
static void schedule_delayed_work(int *work,int delay){(void)work;assert(delay==HZ);}
'''
code += function('rtl_ni_publish')
# Execute the production removal barrier; per-port teardown is covered below and
# by test_lan_probe_isolation, without mocking unrelated DMA/IRQ subsystems.
remove = function('rtl_remove')
barrier = remove[remove.index('\tif (priv->lan4_phy)'):remove.index('\tcancel_delayed_work_sync')]
code += r'''
static void *remove_pending(void *arg){
 struct rtl_xram *priv=arg;
 pthread_mutex_lock(&gate);remove_started=1;pthread_cond_broadcast(&changed);pthread_mutex_unlock(&gate);
''' + barrier + r'''
 assert(worker_finished);remove_passed=1;return NULL;
}
int main(int argc,char **argv){
 assert(argc==5);board_ports=atoi(argv[1]);stage=atoi(argv[2]);remove_mode=atoi(argv[3]);early_mode=atoi(argv[4]);fail_port=4;
 struct net_device primary={.dev_addr={0,0x50,0xc2,1,2,3}};
 struct rtl_xram priv={.netdev=&primary,.qm_rx=true};struct device parent={0};
 for(int i=0;i<5;i++)nodes[i].port=i;
 init_completion(&priv.lan4_ready);
 if(early_mode){
  assert(!pthread_create(&external,NULL,open_external,&priv));
  pthread_mutex_lock(&gate);
  while(!external_has_rtnl)pthread_cond_wait(&changed,&gate);
  pthread_mutex_unlock(&gate);
 }
 assert(!rtl_ni_publish(&priv,&parent));
 if(early_mode){assert(!pthread_join(external,NULL));assert(external_deferred);}
 if(remove_mode)assert(!pthread_create(&remover,NULL,remove_pending,&priv));
 assert(!pthread_join(opener,NULL));
 if(remove_mode)assert(!pthread_join(remover,NULL));
 else if(worker_created)flush_work(&priv.lan4_work);
 assert(opened && priv.engine_users==1 && priv.lan4_ready.done);
 unsigned int expected=board_ports==5?23:15;
 if(board_ports==5 && stage>=1 && stage<=8)expected&=~BIT(4);
 assert(active==expected && priv.registered_ports==expected && fe_ports==expected);
 assert(!node_refs && (!remove_mode || remove_passed));
 for(unsigned int i=0;i<5;i++)assert(priv.qm.lan[i]==priv.ports[i]);
 if(board_ports==5 && !stage)assert(engine_ports&BIT(4));
 for(int i=0;i<5;i++)rtl_unregister_lan(&priv,i);
 assert(!active && !fe_ports && !allocated);
 return 0;
}
'''
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='lan-async-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(code)
    subprocess.run(['cc', '-std=gnu11', '-pthread', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', '-Wno-sign-compare',
                    str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    cases = [(4, 0, 0, 0)] + [(5, fault, remove, 0) for fault in range(10) for remove in (0, 1)]
    cases += [(4, 0, 0, 1), (5, 0, 0, 1), (5, 1, 0, 1), (5, 8, 1, 1)]
    for board, fault, remove, early in cases:
        subprocess.run([str(path / 'test'), str(board), str(fault), str(remove), str(early)],
                       check=True, timeout=5)
    # Recreate the actual bug: making the NI provider openable before LAN
    # registration can acquire RTNL. The external consumer then owns RTNL
    # while waiting for work whose producer is blocked on that same lock.
    mutant=code.replace('\trtl_register_lans(priv, dev);',
                        '\tWRITE_ONCE(priv->provider_ready, true);\n\trtl_register_lans(priv, dev);',1)
    assert mutant!=code
    (path/'mutant.c').write_text(mutant)
    subprocess.run(['cc','-std=gnu11','-pthread','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-Wno-sign-compare',str(path/'mutant.c'),
                    '-o',str(path/'mutant')],check=True)
    result=subprocess.run([str(path/'mutant'),'5','0','0','1'],capture_output=True,text=True,timeout=5)
    assert result.returncode and 'external consumer must defer before LAN registration' in result.stderr,result.stderr
    print(f'{len(cases)} threaded LAN/external early-open, NI4 failure and pending-removal cases passed; early-provider mutant rejected')
