/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compile an EVTO result only when the hardware key covers its dependencies. */
struct fe_evto_result {
 const struct rtl_itu_path *path;
 struct rtl_evto_packet output;
 bool passthrough;
};

static bool fe_evto_equal(const struct rtl_evto_packet *a,const struct rtl_evto_packet *b)
{
 return a->count==b->count && !memcmp(a->tag,b->tag,a->count*sizeof(a->tag[0]));
}
static bool fe_evto_shape(const struct rtl_evto_packet *a,const struct rtl_evto_packet *b)
{
 if(a->count!=b->count)return false;
 for(unsigned int i=0;i<a->count;i++)
  if(a->tag[i].tpid!=b->tag[i].tpid || (a->tag[i].tci&4095)!=(b->tag[i].tci&4095))return false;
 return true;
}
static bool fe_evto_dscp_varies(const u8 map[24])
{
 unsigned int first=rtl_itu_dscp_priority(map,0);

 for(unsigned int d=1;d<64;d++)
  if(rtl_itu_dscp_priority(map,d)!=first)return true;
 return false;
}

/* Cheap per-template bound before the per-PCP reachability walk. A tagged
 * packet cannot reach the unmarked mapper unless a preceding stage can pop
 * a tag; adding or preserving tags cannot make it untagged. Treat any pop
 * as potentially removing all tags, leaving exact reachability to the walk.
 * Only profiles actually referenced by a non-multicast path are relevant. */
static bool fe_evto_may_read_dscp(const struct rtl_itu_paths *paths,
                                const struct rtl_evto_packet *input)
{
 for(unsigned int i=0;i<paths->count;i++) {
  const struct rtl_itu_path *path=&paths->path[i];
  bool untagged=!input->count;

  if(path->multicast)continue;
  for(unsigned int stage=input->service_entry?2:0;stage<RTL_EVTO_STAGES;stage++) {
   unsigned int id=path->vlan_profile[stage];
   bool dscp=false;

   if(id==RTL_EVTO_NONE)continue;
   const struct rtl_evto_profile *profile=&paths->profile[id];
   for(unsigned int n=0;n<profile->count;n++) {
    const u8 *row=profile->row[n];
    unsigned int remove=row[8]>>6;

    if(remove==3)continue; /* A discard row never reads its treatment map. */
    if(stage<3 && remove)untagged=true;
    dscp|=(row[9]&15)==10 || (row[13]&15)==10;
   }
   if(dscp && fe_evto_dscp_varies(profile->dscp))return true;
  }
  if(untagged && path->unmarked_mode==1 && fe_evto_dscp_varies(path->mapper_dscp))return true;
 }
 return false;
}

/* Track a read of a variable DSCP map along the actual upstream row order.
 * The existing row evaluator remains authoritative for matching, edits and
 * drops. Before the first such read, all intermediate tags are independent
 * of DSCP: if this walk does not read it, evaluating DSCP0 proves all64 values.
 * Retain the dependency even if a later stage drops that DSCP0 candidate. */
static int fe_evto_profile_upstream(const struct rtl_evto_profile *profile,
                                  struct rtl_evto_packet *packet,bool *dscp)
{
 for(unsigned int defaults=0;defaults<2;defaults++)
  for(unsigned int n=0;n<profile->count;n++) {
   const u8 *row=profile->row[n];
   int ret;

   if(!!rtl_evto_default(row)!=defaults)continue;
   ret=rtl_evto_up_row(profile,row,packet);
   if(!ret)continue;
   if(ret>0 && ((row[9]&15)==10 || (row[13]&15)==10) &&
      fe_evto_dscp_varies(profile->dscp))*dscp=true;
   return ret>0;
  }
 return 0;
}

static int fe_evto_path_upstream(const struct rtl_itu_paths *paths,
                                const struct rtl_itu_path *path,
                                struct rtl_evto_packet *packet,
                                unsigned int begin,unsigned int end,bool *dscp)
{
 for(unsigned int stage=begin;stage<end;stage++) {
  unsigned int id=path->vlan_profile[stage];

  if(id!=RTL_EVTO_NONE && !fe_evto_profile_upstream(&paths->profile[id],packet,dscp))return 0;
 }
 return 1;
}

/* Conservative reachability, not a second selector: a path that observes
 * variable DSCP asks the real selector below to evaluate every value. Paths
 * rejected before that observation cannot become candidates at another DSCP.
 * Do not prune lower-ranked paths after an observation or infer dependency
 * from unrelated profiles. The mapper is consulted only after the first
 * three stages and only if that intermediate packet is still untagged. */
static bool fe_evto_upstream_dscp(const struct rtl_itu_paths *paths,
                                 const struct rtl_evto_packet *input)
{
 for(unsigned int i=0;i<paths->count;i++) {
  const struct rtl_itu_path *path=&paths->path[i];
  struct rtl_evto_packet packet=*input;
  bool dscp=false;
  int ret;

  if(path->multicast)continue;
  ret=fe_evto_path_upstream(paths,path,&packet,input->service_entry?2:0,2,&dscp);
  if(dscp)return true;
  if(!ret || (path->vlan_exclude&(1U<<packet.priority)) ||
     !rtl_itu_path_matches(path,packet.count?packet.tag[0].tci&4095:RTL_ITU_VLAN_ANY))continue;
  ret=fe_evto_path_upstream(paths,path,&packet,2,3,&dscp);
  if(dscp)return true;
  if(!ret)continue;
  if(!packet.count && path->unmarked_mode) {
   if(path->unmarked_mode==1 && fe_evto_dscp_varies(path->mapper_dscp))return true;
   packet.priority=path->unmarked_mode==1?
    rtl_itu_dscp_priority(path->mapper_dscp,packet.dscp):path->default_priority;
  }
  if(!(path->pbits&(1U<<packet.priority)))continue;
  fe_evto_path_upstream(paths,path,&packet,3,RTL_EVTO_STAGES,&dscp);
  if(dscp)return true;
 }
 return false;
}
static void fe_evto_packet(struct rtl_evto_packet *packet,const struct rtl_fe_vlan *tags,
                           unsigned int count,unsigned int protocol)
{
 *packet=(struct rtl_evto_packet){.count=count,.protocol=protocol};
 for(unsigned int i=0;i<count;i++)
  packet->tag[i]=(struct rtl_evto_tag){tags[i].tpid==1?ETH_P_8021Q:ETH_P_8021AD,
   tags[i].vid|tags[i].priority<<13|tags[i].dei<<12};
 if(count)packet->priority=packet->tag[0].tci>>13;
}
static int fe_evto_output(struct rtl_fe_rule *data,const struct rtl_evto_packet *packet,bool replace)
{
 if(packet->count>2)return -EOPNOTSUPP;
 data->action.vlan_count=packet->count;
 data->action.vlan_set=replace;
 for(unsigned int i=0;i<packet->count;i++) {
  int type=fe_vlan_tpid(htons(packet->tag[i].tpid));
  if(type<0)return type;
  data->action.vlan[i]=(struct rtl_fe_vlan){packet->tag[i].tci&4095,type,
   packet->tag[i].tci>>13,(packet->tag[i].tci>>12)&1};
 }
 data->ethernet_bytes=ETH_HLEN+VLAN_HLEN*packet->count+(data->egress_pppoe?8:0);
 return 0;
}

/* TC L3 keys omit PCP/DEI; exact L2 keys contain both. DSCP and DHCP
 * classifications also need a complete invariant before a MAC/VLAN cache is valid. */
static int fe_evto_invariant(const struct rtl_itu_paths *paths,const struct rtl_evto_packet *prototype,
                             bool unknown_tci,bool bridge,bool downstream,unsigned int gem,
                             struct fe_evto_result *result)
{
 unsigned int variants;
 bool ip=prototype->protocol==ETH_P_IP || prototype->protocol==ETH_P_IPV6 ||
         prototype->protocol==ETH_P_PPP_SES;
 bool maybe_dscp=!downstream && ip && fe_evto_may_read_dscp(paths,prototype);
 bool first=true,constant=true,pass=true;
 if(prototype->count>2)return -EOPNOTSUPP;
 variants=unknown_tci?(prototype->count?1U<<(prototype->count*4):8):prototype->count?1:8;
 for(unsigned int v=0;v<variants;v++)
  for(unsigned int c=0;c<(bridge&&ip?3U:1U);c++) {
   struct rtl_evto_packet input=*prototype;
   unsigned int dscps;

   if(!input.count)input.priority=v;
   else if(unknown_tci) {
    for(unsigned int i=0;i<input.count;i++)input.tag[i].tci=(input.tag[i].tci&4095)|
     ((v>>(i*4))&7)<<13|((v>>(i*4+3))&1)<<12;
    input.priority=input.tag[0].tci>>13;
   }
   if(bridge&&ip) {
    if(c==1 && input.protocol==ETH_P_IPV6)continue;
    if(c==2 && input.protocol==ETH_P_IP)continue;
    input.criteria=c;
   }
   input.dscp=0;
   dscps=maybe_dscp && fe_evto_upstream_dscp(paths,&input)?64:1;
   for(unsigned int d=0;d<dscps;d++) {
    struct rtl_evto_packet output;
    const struct rtl_itu_path *path;

    input.dscp=d;
    path=downstream?rtl_itu_path_receive_vlan(paths,gem,&input,&output):
                    rtl_itu_path_transmit_vlan(paths,&input,&output);
    if(!path || output.count>2)return -EOPNOTSUPP;
    if(first) { result->path=path;result->output=output;first=false; }
    else if(path->index!=result->path->index || path->queue!=result->path->queue)return -EOPNOTSUPP;
    constant&=fe_evto_equal(&output,&result->output);
    pass&=fe_evto_equal(&input,&output);
    if(bridge&&downstream) {
     constant&=output.priority==result->output.priority;
     pass&=output.priority==input.priority;
    }
   }
  }
 if(first || (!constant&&!pass))return -EOPNOTSUPP;
 result->passthrough=pass;
 return 0;
}

static int fe_evto_upstream(struct rtl_fe_rule *data,struct rtl_evto_packet *logical,bool exact)
{
 struct fe_evto_result result;
 bool replace=data->action.vlan_set;
 int ret=fe_evto_invariant(data->input->fe->itu_paths,logical,!exact&&!replace,
                           data->bridge,false,0,&result);
 if(ret)return ret;
 ret=fe_evto_output(data,&result.output,replace||!result.passthrough);
 if(ret)return ret;
 data->action.destination=32+result.path->tcont;data->action.deep_queue=1;
 data->action.cos=result.path->queue;
 data->action.gem_set=1;data->action.gem_index=result.path->index;
 return 0;
}

/* Infer the physical ingress from both the unchanged frame and its upstream
 * image. More than one physical tag/GEM key requires separate hardware rules. */
static int fe_evto_downstream(struct rtl_fe_rule *data,const struct rtl_evto_packet *logical)
{
 struct rtl_itu_paths *paths=data->input->fe->itu_paths;
 struct rtl_evto_packet physical={};
 const struct rtl_itu_path *selected=NULL;
 struct fe_evto_result result;
 unsigned int variants=logical->count?1U<<(logical->count*4):8;
 for(unsigned int n=0;n<paths->count;n++) {
  const struct rtl_itu_path *path=&paths->path[n];
  u16 types[3+RTL_EVTO_STAGES*2]={ETH_P_8021Q,ETH_P_8021AD,0x9100};
  unsigned int type_count=3;
  if(path->multicast || !path->downstream_pbits)continue;
  for(unsigned int stage=0;stage<RTL_EVTO_STAGES;stage++) {
   unsigned int id=path->vlan_profile[stage];
   if(id==RTL_EVTO_NONE)continue;
   for(unsigned int field=0;field<2;field++) {
    u16 type=field?paths->profile[id].output_tpid:paths->profile[id].input_tpid;
    unsigned int i;
    for(i=0;i<type_count && types[i]!=type;i++);
    if(i==type_count)types[type_count++]=type;
   }
  }
  for(unsigned int v=0;v<variants;v++)
   for(unsigned int image=0;image<2;image++) {
    unsigned int dscps=1;

    for(unsigned int d=0;d<dscps;d++) {
     struct rtl_evto_packet candidate=*logical,roundtrip;
     const struct rtl_itu_path *matched;
     bool dependent=false;
     int accepted=1;

     candidate.dscp=d;
     if(!candidate.count)candidate.priority=v;
     else {
      for(unsigned int i=0;i<candidate.count;i++)candidate.tag[i].tci=(candidate.tag[i].tci&4095)|
       ((v>>(i*4))&7)<<13|((v>>(i*4+3))&1)<<12;
      candidate.priority=candidate.tag[0].tci>>13;
     }
     if(image)accepted=fe_evto_path_upstream(paths,path,&candidate,
                        logical->service_entry?2:0,RTL_EVTO_STAGES,&dependent);
     /* The RX inverse evaluator checks the map's possible PCP values, not
      * packet.dscp. Its upstream image can nevertheless take a different
      * tag/GEM shape after a DSCP-dependent intermediate edit. Enumerate
      * those images even if the first DSCP value was dropped later on. */
     if(dependent && (logical->protocol==ETH_P_IP || logical->protocol==ETH_P_IPV6 ||
                      logical->protocol==ETH_P_PPP_SES))dscps=64;
     if(!accepted)continue;
     for(unsigned int a=0;a<(candidate.count?type_count:1U);a++)
      for(unsigned int b=0;b<(candidate.count==2?type_count:1U);b++) {
       struct rtl_evto_packet wire=candidate;
       if(wire.count)wire.tag[0].tpid=types[a];
       if(wire.count==2)wire.tag[1].tpid=types[b];
       matched=rtl_itu_path_receive_vlan(paths,path->index,&wire,&roundtrip);
       if(!matched || !fe_evto_shape(&roundtrip,logical))continue;
       if(wire.count>2 || (selected && (selected->index!=matched->index ||
          !fe_evto_shape(&physical,&wire))))return -EOPNOTSUPP;
       physical=wire;selected=matched;
      }
    }
   }
 }
 if(!selected || physical.count>2)return -EOPNOTSUPP;
 int ret=fe_evto_invariant(paths,&physical,true,data->bridge,true,selected->index,&result);
 if(ret || !fe_evto_shape(&result.output,logical))return -EOPNOTSUPP;
 if(!data->action.vlan_set) {
  ret=fe_evto_output(data,&result.output,!result.passthrough);
  if(ret)return ret;
 }
 data->vlan_count=physical.count;
 for(unsigned int i=0;i<physical.count;i++) {
  int type=fe_vlan_tpid(htons(physical.tag[i].tpid));
  if(type<0)return type;
  data->vlan[i]=(struct rtl_fe_vlan){.vid=physical.tag[i].tci&4095,.tpid=type};
 }
 data->key.llid=selected->index;data->key6.llid=selected->index;
 return 0;
}

static int fe_itu_rule(struct rtl_fe_rule *data)
{
 struct rtl_fe *fe=data->input->fe;
 struct rtl_evto_packet packet;
 unsigned int protocol=data->bridge?data->ethernet_protocol:data->pppoe_input?ETH_P_PPP_SES:
                       data->ipv6?ETH_P_IPV6:ETH_P_IP;
 if(data->input->netdev==fe->itu_netdev) {
  fe_evto_packet(&packet,data->vlan,data->vlan_count,protocol);
  packet.service_entry=!data->bridge && packet.count;
  if(!data->bridge && data->key.protocol==IPPROTO_UDP) {
   unsigned int a=data->key.source_port,b=data->key.destination_port;
   if(!data->ipv6&&(a==67||a==68)&&(b==67||b==68))packet.criteria=1;
   if(data->ipv6&&(a==546||a==547)&&(b==546||b==547))packet.criteria=2;
  }
  if(!fe->itu_paths->profile_count) {
   const struct rtl_itu_path *path=rtl_itu_path_downstream(fe->itu_paths,
    data->vlan_count?data->vlan[0].vid:RTL_ITU_VLAN_ANY,255);
   if(!path)return -EOPNOTSUPP;
   data->key.llid=data->key6.llid=path->index;
  } else if(fe_evto_downstream(data,&packet))return -EOPNOTSUPP;
 }
 if(data->output->netdev==fe->itu_netdev) {
  protocol=data->egress_pppoe?ETH_P_PPP_SES:data->bridge?data->ethernet_protocol:
           data->ipv6?ETH_P_IPV6:ETH_P_IP;
  fe_evto_packet(&packet,data->action.vlan,data->action.vlan_count,protocol);
  packet.service_entry=!data->bridge && packet.count;
  if(!data->bridge && data->key.protocol==IPPROTO_UDP) {
   unsigned int a=data->key.source_port,b=data->key.destination_port;
   if(data->action.translate) {
    if(data->action.translate_destination)b=data->action.port;else a=data->action.port;
   }
   if(!data->ipv6&&(a==67||a==68)&&(b==67||b==68))packet.criteria=1;
   if(data->ipv6&&(a==546||a==547)&&(b==546||b==547))packet.criteria=2;
  }
  if(fe_evto_upstream(data,&packet,data->vlan_exact))return -EOPNOTSUPP;
 }
 return 0;
}
