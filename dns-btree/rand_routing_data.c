#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <arpa/inet.h>

static char speak_lvls = 1;

#define set_speaking_off()           speak_lvls = 0
#define set_speaking_level(levels)   speak_lvls = 1 | (levels)

#define debug_dump(level, str, structure) \
  if (speak_lvls & level) { \
    int ii; \
    unsigned char *p_b = (unsigned char *)&((structure)); \
    printf("%s", (str)); for (ii=0; ii<sizeof((structure)); printf("%02x:", p_b[ii++])); printf("\n"); \
  }

#define speakout(level, ...) \
  if (speak_lvls & level) printf(__VA_ARGS__)

#define SPK_ERR    1
#define SPK_APP    2
#define SPK_CALL   4
#define SPK_RECR   8
#define SPK_DTL    16

#define DEFAULT_VERBOSITY (SPK_ERR | SPK_APP)

#define SUBNET_MASK_BITS  56
#define SUBNET_MASK_BYTES (SUBNET_MASK_BITS / 8)

#define TRUE 1

#define INVALID_INDEX -1

#define USE_MMAP 

#define MMAP_FILENAME "file.mmap"

typedef struct in_addr  T_ROUT_IP4;
typedef struct in6_addr T_ROUT_IP6;

typedef struct s_ip64_pair {
  T_ROUT_IP4  ip4;
  T_ROUT_IP6  ip6;
} T_IP64_PAIR;

typedef struct s_ip6_net {
  unsigned char net[SUBNET_MASK_BYTES];
} T_IP6_NET;

typedef struct s_rout_btree_node {
  T_IP6_NET       key6;
  struct in_addr  val4;
  unsigned int    lindex;
  unsigned int    rindex;
} T_ROUT_BTREE_NODE;

typedef struct s_chunk  {
  unsigned int next_free;
} T_CHUNK;

// overlayed two structures - list of free chunks (aligned unused nodes) and linked btree nodes
typedef union s_rout_chunk {
  T_CHUNK chunk;
  T_ROUT_BTREE_NODE node;
} T_ROUT_CHUNK;

typedef struct t_rout_btree {
  unsigned int       first_free;
  unsigned int       first_unused;
  unsigned int       nnodes;
  unsigned int       count_free;
  unsigned int       tree_root;
} T_ROUT_BTREE_HNDL;

typedef struct t_rout_data {
  T_ROUT_BTREE_HNDL  *tree;
  bool               load;
  unsigned int       bytes;
} T_ROUT_DATA;

typedef struct t_rout_btree_step_ctx {
  T_ROUT_BTREE_NODE *base;
  int best_index;
  int preflen;
} T_ROUT_BTREE_STEP_CTX;

typedef enum e_rout_update {
  E_ROUT_NONE = 0,
  E_ROUT_MATCH,
  E_ROUT_LEFT,
  E_ROUT_RIGHT,
  E_ROUT_INSERT_JOIN_LEFT,
  E_ROUT_INSERT_JOIN_RIGHT
} E_ROUT_BTREE_RESULT;

/*
 *
 * x...unused, U...used, F...free (initialized)
 *
 * time 0:00 F->x x x x x ...
 *
 * time 1:00 U->U->U U F->x x x x x 
 *              +----^
 *
 *             +------v
 * time 2:00 U F U->U F->F->F x x x x
 *           +---^
 *
 */
T_ROUT_BTREE_HNDL *rout_btree_init(unsigned int nnodes, T_ROUT_DATA *p_rdata)
{
  T_ROUT_BTREE_HNDL *p_tree;
  T_ROUT_CHUNK *p_chunk;
  unsigned int nbytes = (nnodes + 1) * sizeof(T_ROUT_CHUNK);
  int fd = 0;
  int err;
  struct stat statbuf;
  int protect = PROT_READ | PROT_WRITE;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int size;

  assert(sizeof(T_ROUT_BTREE_HNDL) <= sizeof(T_ROUT_CHUNK));


#ifdef USE_MMAP
  if (p_rdata->load)
  {
    fd = open(MMAP_FILENAME, O_RDWR);

    if (fd < 0) {
      printf("\n\"%s\" could not open. Try option -G first.\n", MMAP_FILENAME);
      exit(1);
    }
    if (fstat(fd, &statbuf) < 0) {
      printf("\n\"%s \" could not open\n", MMAP_FILENAME);
      exit(2);
    }
    size    = statbuf.st_size;
    protect = PROT_READ;
    flags   = MAP_SHARED;
    p_rdata->bytes = size;
  }
  else
  {
    size = (nnodes + 1) * sizeof(T_ROUT_CHUNK);
  }

  speakout(SPK_CALL, "rout_btree_init: load: %d, bytes: %d\n", p_rdata->load, size);

  p_tree = mmap(NULL, size, protect, flags, fd, 0 );

  if (p_tree == MAP_FAILED)
  {
    speakout(SPK_ERR, "Mapping failed.\n");
    exit(1);
  }
  close(fd);

#else
  // one chunk extra for the tree handle
  p_tree = (T_ROUT_BTREE_HNDL *)calloc((size_t)(nnodes + 1), sizeof(T_ROUT_CHUNK));
  if (p_tree == NULL)
  {
    speakout(SPK_ERR, "Not enough memory?\n");
    exit(1);
  }
#endif

  if (!p_rdata->load)
  {
    p_tree->first_free = p_tree->first_unused = 0;
    p_tree->tree_root  = INVALID_INDEX;
    p_tree->count_free = nnodes;
    p_tree->nnodes     = nnodes;
    
    // make ready the first chunk
    p_chunk = ((T_ROUT_CHUNK *)(&p_tree[1]));
    p_chunk->chunk.next_free = 1; //lazy init, we'are at '0', next is '1'
  }

  speakout(SPK_CALL, "rout_btree_init: p_tree: %p\n");

  p_rdata->tree = p_tree; 
  return p_tree;
}

void rout_btree_deinit(T_ROUT_DATA *rdata)
{
  T_ROUT_BTREE_HNDL *p_tree = rdata->tree;
  bool dump2file = !rdata->load;
  size_t written;
  FILE *f1;

  if (dump2file == true)
  {
    f1 = fopen(MMAP_FILENAME, "wb");
    if (!f1) {
        printf("File opening failed\n");
    }
    else
    {
      written = fwrite(p_tree, sizeof(T_ROUT_CHUNK) * (p_tree->nnodes + 1), 1, f1);
      printf("Routing data saved into %s, wrote %zu element(s).\n\n", MMAP_FILENAME, written);
      fclose(f1);
    }
  }

#ifdef USE_MMAP
  munmap(p_tree, rdata->bytes);
#else
  free(p_tree);
#endif
  return;
 
}

T_ROUT_BTREE_NODE *rout_btree_get_node(T_ROUT_BTREE_HNDL *p_tree)
{
  T_ROUT_CHUNK *pool = (T_ROUT_CHUNK *)(&p_tree[1]);
  T_ROUT_CHUNK *p_chunk;

  speakout(SPK_CALL, "rout_btree_get_node: size: %d, root: %d, first free: %d, first unused: %d, free: %d\n", 
            p_tree->nnodes, 
            p_tree->tree_root,
            p_tree->first_free, 
            p_tree->first_unused, 
            p_tree->count_free); 


  if (p_tree->count_free == 0)
  {
    speakout(SPK_ERR, "No more nodes.\n");
    return NULL;
  }
  // assert(p_tree->first_free <= p_tree->first_unused)

  p_tree->count_free -= 1;
  if (p_tree->first_free == p_tree->first_unused)
  {
    // head of free = tail of free
    p_chunk = &pool[p_tree->first_unused];
    // unused chunks are ordered one by one in an array with no explicit linking -> thus use the pointer arithmetic here
    p_tree->first_free = ++p_tree->first_unused;
  }
  else 
  {
    p_chunk = &pool[p_tree->first_free];
    p_tree->first_free = p_chunk->chunk.next_free;
  }
  speakout(SPK_CALL, "rout-btree_get_node: new node: %p\n\n", p_chunk);

  return ((T_ROUT_BTREE_NODE *)p_chunk);
}

int rout_btree_release_node(T_ROUT_BTREE_HNDL *p_tree, T_ROUT_BTREE_NODE *p_node)
{
  T_ROUT_CHUNK *pool = (T_ROUT_CHUNK *)(&p_tree[1]);
  T_ROUT_CHUNK *p_chunk     = (T_ROUT_CHUNK *)p_node;

  if (p_tree->count_free < p_tree->nnodes)
  {
    // alter the head of free chunks
    p_chunk->chunk.next_free = p_tree->first_free;
    p_tree->first_free = p_chunk - pool; // what is my index?
    p_tree->count_free += 1;
  }
  return 0;
}

int rout_btree_node_set_value(T_ROUT_BTREE_NODE *p_node, struct in_addr ip4addr)
{
  if (p_node != NULL)
  {
    p_node->val4   = ip4addr;
  }
  return 0;
}

int rout_btree_insert_node(T_ROUT_BTREE_HNDL *p_tree, T_IP6_NET ip6net)
{
  T_ROUT_BTREE_NODE *p_node;
  T_ROUT_BTREE_NODE *nodepool = (T_ROUT_BTREE_NODE *)(&p_tree[1]);

  p_node = rout_btree_get_node(p_tree);

  if (p_node != NULL)
  {
    p_node->key6   = ip6net;
    // set new node as a leaf
    p_node->rindex = p_node->lindex = (unsigned int)INVALID_INDEX;

    return (p_node - nodepool);
  }
  return INVALID_INDEX;
}

int rout_btree_cmp_ip6nets(T_IP6_NET *a, T_IP6_NET *b, int *preflen)
{
  unsigned char *pa = (unsigned char *)a; // &a->net
  unsigned char *pb = (unsigned char *)b; // &b->net
  unsigned char m;
  int len, i, k, diff;

  *preflen = 0;
  for(i = 0; (i < SUBNET_MASK_BYTES - 1) && (pa[i] == pb[i]); i++) ; // empty block

  len = (i * 8);
  m = ~(pa[i] ^ pb[i]);
  for(k = 0; k < 8; k++) if (!((m << k) & 0x80)) break;
  len += k;

  diff = pa[i] - pb[i];

  if (diff == 0)
  {
    *preflen = len; // full match
  }
  else
  {
    // some matching prefix, but the rest must be zero in order to say "b" belongs to "a" network
    do {
      m = (0x1 << (8 - k)) - 1;
      if (pa[i] & m) break;

      for(k = i; (k < SUBNET_MASK_BYTES) && (pa[k] == 0x00); k++) ; /// empty block

      speakout(SPK_CALL, "is subnet? m=%02x, k=%d\n", m, k);

      if (k < SUBNET_MASK_BYTES) break;

      // "b" is really part of the subnet "a"
      *preflen = len; 
    } while(0);
  }
 
  speakout(SPK_CALL, "rout_btree_cmp_ip6nets, differing in %d byte (%02x, %02x), preflen: %d\n", 
                     i + 1, pa[i], pb[i], *preflen);
  return diff;
}

E_ROUT_BTREE_RESULT rout_btree_eval_ip6nets(T_IP6_NET *a, T_IP6_NET *b)
{
  unsigned char *pa = (unsigned char *)a; // &a->net
  unsigned char *pb = (unsigned char *)b; // &b->net
  unsigned char n, x, lvln, lvlx;
  int i, k;

  for(i = 0; (i < SUBNET_MASK_BYTES - 1) && (pa[i] == pb[i]); i++) ; // empty block

  speakout(SPK_CALL, "rout_btree_eval_ip6nets, differing in %d byte (%02x, %02x)\n", i + 1, pa[i], pb[i]);
 
  // the highest differing bytes 
  n = pa[i]; // in the tree
  x = pb[i]; // in what we are looking for

  if (n == x) return E_ROUT_MATCH; // both keys must be equal

  return (x > n) ? E_ROUT_RIGHT : E_ROUT_LEFT;
}

int rout_btree_remove_node(T_ROUT_BTREE_HNDL *p_tree, T_ROUT_BTREE_NODE *p_node)
{
  // TODO
  // - is it a leaf?
  // - does it have one leaf?
  // - does it have two leafs?
  // - finally rout_btree_release_node(p_tree, p_node);
}

T_ROUT_BTREE_NODE *rout_btree_step(T_ROUT_BTREE_STEP_CTX *p_stepctx, unsigned int par_index, T_IP6_NET ip6net, int *p_hops)
{
  T_ROUT_BTREE_NODE *base = p_stepctx->base;
  unsigned int rindex, lindex, index;
  int k, preflen;

  if (par_index == INVALID_INDEX) return NULL;

  lindex = base[par_index].lindex;
  rindex = base[par_index].rindex;
  *p_hops += 1;
 
  k = rout_btree_cmp_ip6nets(&base[par_index].key6, &ip6net, &preflen);

  speakout(SPK_CALL,  "rout_btree_step: addr: %p, cur_index/result of compare: %d/%d\n", 
                 &base[par_index], par_index, k);
  debug_dump(SPK_CALL, "current key: ", base[par_index].key6);

  if (k == 0)
  {
    p_stepctx->preflen    = preflen;
    p_stepctx->best_index = par_index;
    return &base[par_index]; // exact match
  }

  // check the best scope prefix
  if (p_stepctx->preflen < preflen)
  {
    p_stepctx->preflen    = preflen;
    p_stepctx->best_index = par_index;
  }

  // inspect right or left sub-nodes 
  index = (k < 0) ? base[par_index].rindex : base[par_index].lindex;
  speakout(SPK_CALL, "rout_btree_step: next index: %d (%s)\n", index, (k < 0)?"right":"left");
  
  if (index == INVALID_INDEX)
  {
    speakout(SPK_CALL, "rout_btree_step: no more nodes to inspect, return the best match.\n");
    if (p_stepctx->preflen > 0)
      return(&base[p_stepctx->best_index]);
    else
      return NULL; 
  }
  
  return rout_btree_step(p_stepctx, index, ip6net, p_hops);
}

T_ROUT_BTREE_NODE *rout_btree_step_or_update(T_ROUT_BTREE_HNDL *p_tree, unsigned int *p_from, T_IP6_NET *p_ip6net)
{
  T_ROUT_BTREE_NODE *nodepool = (T_ROUT_BTREE_NODE *)(&p_tree[1]);
  E_ROUT_BTREE_RESULT res;
  unsigned int *p_link;
  unsigned int cur_index, new_index;

  speakout(SPK_CALL, "rout_btree_step_or_update: %d\n", *p_from);

  res       = E_ROUT_NONE;
  p_link    =  p_from;
  cur_index = *p_from;

  if (cur_index != INVALID_INDEX)
  {

    res = rout_btree_eval_ip6nets(&nodepool[cur_index].key6, p_ip6net);
    speakout(SPK_CALL, "evaluation result: %d\n", res);

    p_link  = (res == E_ROUT_LEFT) ? &(nodepool[cur_index].lindex) : &(nodepool[cur_index].rindex);
  }

  if (res == E_ROUT_MATCH)
  {
    // return this node
    return &(nodepool[cur_index]);
  }

  if (*p_link == INVALID_INDEX)
  {
    // squeeze in or no more node to inspect, add a new one
    new_index = rout_btree_insert_node(p_tree, *p_ip6net);
 
    if (new_index == INVALID_INDEX) return NULL;

    *p_link = new_index;

    return (&nodepool[new_index]);

  }
  else
  {
    // inspect next node
    return rout_btree_step_or_update(p_tree, p_link, p_ip6net);
  }
  return NULL;
}

int rout_btree_update(T_ROUT_BTREE_HNDL *p_tree, struct in6_addr ip6addr, struct in_addr ip4addr)
{
  T_IP6_NET ip6net;
  T_ROUT_BTREE_NODE *p_node;

  speakout(SPK_CALL, "rout_btree_update: %p\n", p_tree);

  ip6net = *(T_IP6_NET *)&ip6addr;
  
  p_node = rout_btree_step_or_update(p_tree, &p_tree->tree_root, &ip6net);

  return rout_btree_node_set_value(p_node, ip4addr);
}

T_ROUT_BTREE_NODE *rout_btree_find_node(T_ROUT_BTREE_HNDL *p_tree, struct in6_addr ip6addr)
{
  T_ROUT_BTREE_NODE *p_node;
  T_ROUT_BTREE_NODE *nodepool = (T_ROUT_BTREE_NODE *)(&p_tree[1]);
  T_ROUT_BTREE_STEP_CTX stepctx;
  T_IP6_NET ip6net = {0};
  struct in6_addr found_addr = {0};
  char buf[64];
  int par_node = p_tree->tree_root;
  struct timeval stop, start;
  int hops = 0;

  speakout(SPK_CALL, "rout_btree_find_node: %p\n", p_tree);

  stepctx.base       = nodepool;
  stepctx.preflen    = 0;
  stepctx.best_index = INVALID_INDEX;

  gettimeofday(&start, NULL);

  ip6net = *(T_IP6_NET *)&ip6addr;
  
  speakout(SPK_CALL, "Input (IPv6 pref): %s\n", inet_ntop(AF_INET6, &ip6addr, buf, sizeof(buf)));
  debug_dump(SPK_APP, "Input dump IPv6: ", ip6addr);

  p_node = rout_btree_step(&stepctx, par_node, ip6net, &hops);

  gettimeofday(&stop, NULL);

  speakout(SPK_APP, "Found: %p and it took %lu microseconds and %d hops.\n", 
                    p_node, 
                    (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec, 
                    hops);
  if (p_node)
  {
    memcpy(&found_addr, &p_node->key6, sizeof(p_node->key6));
    speakout(SPK_APP, "Best match %s/%d, corresponding value (IPv4) %s\n\n", 
                      inet_ntop(AF_INET6, &found_addr, buf, sizeof(buf)),
                      stepctx.preflen,
                      inet_ntoa(p_node->val4));
  }
  return p_node;
}

int gen_rand_routing_pair(T_IP64_PAIR *p_pair)
{
  unsigned int i, len6;
  char *p;
  char buf[64];
  unsigned char m;

  p = (char *)p_pair;
  for( i = 0; i < sizeof(T_IP64_PAIR) ; p[i++] = rand() % 256 );

  len6 = 8 + rand() % 120; // rand 8 .. 128
  p = ((char *)&p_pair->ip6) + (len6 / 8);
  memset(p, '\0', sizeof(p_pair->ip6) - (len6 / 8));
  if (len6 % 8)
  {
    p++;
    m = (0x80 >> ((len6 % 8) - 1)) - 1;
    m = ~m;
    *p = *p & m;
  }  
  speakout(SPK_APP, "prefix length/mask end: %d/0x%02x\n", len6, m);
  speakout(SPK_APP, "%s->%s\n", inet_ntop(AF_INET6, &p_pair->ip6, buf, sizeof(buf)),
                                inet_ntoa(p_pair->ip4));

  return 0;

}

void rout_btree_node_stats(T_ROUT_BTREE_HNDL *p_tree, 
                           unsigned int index, unsigned int *p_nfull, unsigned int *p_nlo, unsigned int *p_nro, unsigned int *p_nleafs)
{
  T_ROUT_BTREE_NODE *p_nodes = (T_ROUT_BTREE_NODE *)(&p_tree[1]);
  T_ROUT_BTREE_NODE *p_node;
  unsigned int lindex, rindex;

  if (index == INVALID_INDEX) return;

  p_node = &p_nodes[index];
  lindex = p_node->lindex;
  rindex = p_node->rindex;

  if ((lindex == INVALID_INDEX) && (rindex == INVALID_INDEX))
  {
    *p_nleafs += 1;
    return;
  }

  if ((lindex != INVALID_INDEX) && (rindex != INVALID_INDEX))
  {
    *p_nfull += 1;
  }
  else if (rindex != INVALID_INDEX)
  {
    *p_nro += 1;
  }
  else // if (lindex != INVALID_INDEX)
  {
    *p_nlo += 1;
  }
  rout_btree_node_stats(p_tree, lindex, p_nfull, p_nlo, p_nro, p_nleafs);
  rout_btree_node_stats(p_tree, rindex, p_nfull, p_nlo, p_nro, p_nleafs);
  return;
}

void rout_btree_node_dump(T_ROUT_BTREE_NODE *p_node, int index)
{
  static int lvl = SPK_CALL;

  if ((speak_lvls & lvl) == 0) return;

  speakout(lvl, "node address: %p/%d\n", p_node, index);
  debug_dump(lvl, "Dump key:     ", p_node->key6)
  speakout(lvl, "Dump value:   %s\n", inet_ntoa(p_node->val4));
  speakout(lvl, "left child: %d, right child: %d\n\n", p_node->lindex, p_node->rindex);
  return;
}

void rout_btree_index_dump(T_ROUT_BTREE_HNDL *p_tree, int index)
{
  T_ROUT_BTREE_NODE *p_node;

  p_node = (T_ROUT_BTREE_NODE *)(&p_tree[1]);
  rout_btree_node_dump(&p_node[index], index);
  return;
}

void rout_btree_dump(T_ROUT_BTREE_HNDL *p_tree)
{
  T_ROUT_BTREE_NODE *p_nodes;
  p_nodes = (T_ROUT_BTREE_NODE *)(&p_tree[1]);
  int i = 0;

  speakout(SPK_APP, "\nTree dump\n");
  speakout(SPK_APP, "size: %d, root: %d, first free: %d, first unused: %d, free: %d\n\n", 
          p_tree->nnodes, 
          p_tree->tree_root,
          p_tree->first_free, 
          p_tree->first_unused, 
          p_tree->count_free); 

  speakout(SPK_APP, "\n...Use option -v to see the nodes...\n");

  for (i = 0; i < p_tree->nnodes; i++)
  {
    rout_btree_node_dump(&p_nodes[i], i);
  }

  {
    int nfull, nlo, nro, nleafs;
    nfull = nlo = nro = nleafs = 0;
    rout_btree_node_stats(p_tree, p_tree->tree_root, &nfull, &nlo, &nro, &nleafs);
    speakout(SPK_APP, "\nTree stats:\n");
    speakout(SPK_APP, "full nodes: %d, left child only: %d, right child only: %d, leafs: %d\n\n", 
                      nfull, nlo, nro, nleafs);
  }

}

int main (int argc, char *argv[])
{
  T_ROUT_DATA rdata;
  T_ROUT_BTREE_HNDL *p_tree;
  // From the task
  char *str4 = "25.8.129.14";
  char *str6 = "2600:170F:1920:0000::";
  char buf[64];
  char pref2test[64];
  bool b_gen = true;
  int c, tree_size;
  T_ROUT_BTREE_NODE *p_node;

  T_IP64_PAIR pair, pair77;

  set_speaking_level(SPK_ERR | SPK_APP); // | SPK_CALL | SPK_DTL

  c = getopt(argc, argv, "vg:G:t:T:");
  do {
    switch (c) {
      case 't': 
      case 'T': 
        speakout(SPK_APP, "Routing data to be loaded from a file.\n");
        memcpy(pref2test, optarg, sizeof(pref2test));
        b_gen = false;
        break;
     case 'g':
     case 'G':
        speakout(SPK_APP, "Routing data to be generated and saved into a file.\n");
        tree_size = atoi(optarg);
        break;
     case 'v':
        set_speaking_level(SPK_ERR | SPK_APP | SPK_CALL); // | SPK_DTL
        break;
     default:
        speakout(SPK_APP, "Usage: <binary> -v | -G <number of nodes> | T <IPv6 net>\n");
        exit(1);
    }
  } while ((c = getopt(argc, argv, "vg:G:t:T:")) != -1);

  // Some playground
  speakout(SPK_DTL, "sizeof T_ROUT_BTREE_NODE: %d\n", sizeof(T_ROUT_BTREE_NODE));
  speakout(SPK_DTL, "sizeof T_ROUT_BTREE_HNDL: %d\n", sizeof(T_ROUT_BTREE_HNDL));
  //printf("size of T_IP64_PAIR: %d\n", sizeof(T_IP64_PAIR));

  if (inet_aton(str4, &pair77.ip4) == 1) //success
  {
  }
  else { printf("IPv4 parsing failed.\n"); return -1; } 

  debug_dump(SPK_APP, "Dump IPv4: ", pair77.ip4)

  if (inet_pton(AF_INET6, str6, &pair77.ip6) == 1) //success!
  {
  }
  else { printf("IPv6 parsing failed.\n"); return -1; } 

  debug_dump(SPK_APP, "Dump IPv6: ", pair77.ip6)

  // Init the tree

#define TREE_SIZE 12800
  rdata.load = !b_gen;
  p_tree = rout_btree_init(tree_size, &rdata);

  //rout_btree_dump(p_tree);

#define CHECK_TREE
#define NUM_OF_CHECKS 5
  if (b_gen == true)
  {
    T_IP6_NET nets2look[NUM_OF_CHECKS];
    int       perc2look[NUM_OF_CHECKS] = {10, 30, 50, 70, 90};
    time_t t;
    int i, k;

    srand((unsigned)time(&t));

    for (i = k = 0; i<99*tree_size/100; i++) 
    {
      gen_rand_routing_pair(&pair);
      //if ((k < NUM_OF_CHECKS) && (i == 77*tree_size/100)) pair = pair77;
  
#ifdef CHECK_TREE
      if ((k < NUM_OF_CHECKS) && (i == perc2look[k]*tree_size/100)) nets2look[k++] = *(T_IP6_NET *)&(pair.ip6);
#endif
      rout_btree_update(p_tree, pair.ip6, pair.ip4);
      
      //speakout(SPK_ERR, "New #%d - ", i);

    }
    rout_btree_dump(p_tree);

    // find a node at X%
 #ifdef CHECK_TREE
    for (k = 0; k < NUM_OF_CHECKS; k++)
    {
      struct in6_addr prefix6 = {0};

      //prefix6 = *(struct in6_addr *)&nets2look[k];
      memcpy(&prefix6, &nets2look[k], SUBNET_MASK_BYTES);

      speakout(SPK_APP, "\n\nSearching for the prefix %s inserted at %d%% od tree filling.\n\n",
                        inet_ntop(AF_INET6, &prefix6, buf, sizeof(buf)),
                        perc2look[k]);

      p_node = rout_btree_find_node(p_tree, prefix6);
    }
#endif
  }
  else
  {
    struct in6_addr test6 = {0};

    rout_btree_dump(p_tree);

    inet_pton(AF_INET6, pref2test, &test6);

    speakout(SPK_APP, "\n\nSearching for the prefix %s\n\n", pref2test);
    debug_dump(SPK_DTL, "Dump IPv6: ", test6)

    p_node = rout_btree_find_node(p_tree, test6);
  }

  // de-init and dump to a file
  rout_btree_deinit(&rdata);

  return 0;
}
