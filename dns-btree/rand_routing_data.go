package main

import ( 
       "os"
       "fmt"
       "net"
       "math/rand"
       "strconv"
       "log"
       "reflect"
       "unsafe"
       "flag"
 )

var gParam = flag.Int("g", 32, "Amount of the generated routing data")

const (
  IPv6nlen = 7
  btreeInvalidIndex = ^uint32(0)
)

type RoutBtreePoolCtl struct {
  firstFree   uint32
  firstUnused uint32
  nNodes      uint32
  countFree   uint32
  treeRoot    uint32
  indexes     map[*RoutBtreeNode]uint32
} 

type RoutBtreeNode struct {
  key6 [IPv6nlen]byte
  val4 uint32
  lindex uint32
  rindex uint32
}

type RoutBtree struct {
  ctl   RoutBtreePoolCtl
  nodes []RoutBtreeNode
} 

func (n *RoutBtreeNode) SetNextFree(next uint32) {
  n.key6[0] = byte((next & 0xFF000000) >> 24)
  n.key6[1] = byte((next & 0x00FF0000) >> 16)
  n.key6[2] = byte((next & 0x0000FF00) >> 8)
  n.key6[3] = byte((next & 0x000000FF))
}

func (n *RoutBtreeNode) GetNextFree() uint32 {
  return uint32(n.key6[0] << 24 + n.key6[1] << 16 + n.key6[2] << 8 + n.key6[3])
}

func (n *RoutBtreeNode) Link(res int) *uint32 {
  if (res > 0) { return &n.rindex }
  if (res < 0) { return &n.lindex }
  return nil
}

func RandomPair64() (net.IPNet, net.IP) {
  ip6 := net.IPv6zero
  a   := byte(rand.Intn(255))
  b   := byte(rand.Intn(255))
  c   := byte(rand.Intn(255))
  d   := byte(rand.Intn(255))
  ip4 := net.IPv4(a, b, c, d)
 
  for i:=0; i<net.IPv6len; i++ {
    ip6[i] = byte(rand.Intn(255))
  }
  _, net6, err := net.ParseCIDR(ip6.String() + "/" + strconv.Itoa(8 + rand.Intn(49)))
  if err != nil {
    log.Fatal(err)
  }
  return *net6, ip4
}

func GeneratorIP6NetIP4(count int) (chan net.IPNet, chan net.IP) {
  c6 := make(chan net.IPNet)
  c4 := make(chan net.IP)

  go func() {
    defer close(c6)
    defer close(c4)
    for i:= 0; i<count; i++ {
      net6, ip4 := RandomPair64()
      
      c6 <- net6
      c4 <- ip4
    }
  }()

  return c6, c4
}

func IPToUint32(ip net.IP) uint32 {
  a4 := ip.To4()

  // consider endianess of the target platform
  return (uint32(a4[3]) << 24 + uint32(a4[2]) << 16 + uint32(a4[1]) << 8 + uint32(a4[0]))
}

func (tree *RoutBtree) Init(nodes uint32) []RoutBtreeNode {
  
  tree.nodes = make([]RoutBtreeNode, 1, nodes)

  tree.ctl.firstFree   = 0
  tree.ctl.firstUnused = 0
  tree.ctl.countFree   = nodes
  tree.ctl.nNodes      = nodes
  tree.ctl.treeRoot    = btreeInvalidIndex

  //fmt.Printf("[0] = %p\n", &tree.nodes[0])
  //fmt.Printf("[1] = %p\n", &tree.nodes[1])

  tree.ctl.indexes = make(map[*RoutBtreeNode]uint32)
  return tree.nodes
}

func (tree *RoutBtree) GetNode() *RoutBtreeNode {
  ctl := &(tree.ctl)
  //fmt.Printf("GetNode.enter: %p, %#v\n", ctl, ctl)

  if (ctl.countFree == 0) {
    fmt.Printf("No more nodes.\n")
    return nil
  }

  defer func () {ctl.countFree -= 1}()

  if (ctl.firstFree == ctl.firstUnused) {

    tree.nodes = append(tree.nodes, RoutBtreeNode{})
    defer func () {ctl.firstUnused++; ctl.firstFree = ctl.firstUnused}()

  } else {

    defer func () {ctl.firstFree = tree.nodes[ctl.firstFree].GetNextFree()}()

  }

  ctl.indexes[&(tree.nodes[ctl.firstFree])] = ctl.firstFree
  tree.nodes[ctl.firstFree].lindex = btreeInvalidIndex
  tree.nodes[ctl.firstFree].rindex = btreeInvalidIndex

  //fmt.Printf("node[%d]: %p\n", ctl.firstFree, &tree.nodes[ctl.firstFree])
  //fmt.Printf("GetNode.exit: %p, %#v\n", ctl, ctl)

  return &tree.nodes[ctl.firstFree] 
}

func (tree *RoutBtree) Insert(net6 *net.IPNet, ip4 *net.IP) {
  var link *uint32
  var innerFunc func(*uint32) *RoutBtreeNode

  ip6 := net6.IP

  fmt.Printf("Insert.key: %s\n", ip6)
  fmt.Printf("Insert.val: %s\n", ip4)

  innerFunc = func(xxx *uint32) *RoutBtreeNode {

    if (*xxx != btreeInvalidIndex) {

      node := &tree.nodes[*xxx]
      //fmt.Printf("Node[%d] to inspect: %p, %#v\n", tree.ctl.indexes[node], node, node)

      var res int
      for i, v := range node.key6 {

        res = int(ip6[i]) - int(v)
        //fmt.Printf("%#v-%#v=%#v\n", ip6[i], v, res)
        if (res != 0) { break }
      }
      link = node.Link(res)
    } else {
      link = xxx
    }
    //fmt.Printf("link: %p, %#v\n", link, *link)

    // Match
    if (link == nil) { 

      return &tree.nodes[*xxx] 
    } else if (*link == btreeInvalidIndex) {

      // no more nodes to inspect, insert new one
      newNode := tree.GetNode()
      *link = tree.ctl.indexes[newNode]
      copy(newNode.key6[:IPv6nlen], ip6[:IPv6nlen])

      return newNode
    } else {

      return innerFunc(link)
    }
    return nil
  }

  fmt.Printf("treeRoot: %#v\n", tree.ctl.treeRoot)

  mynode := innerFunc(&tree.ctl.treeRoot)

  if (mynode != nil) {
    // set or update
    mynode.val4 = IPToUint32(*ip4)
    fmt.Printf("Set node[%d]: %p, %#v\n", tree.ctl.indexes[mynode], mynode, mynode)
  }
}

func (tree *RoutBtree) WriteToFile(fn string) error {

  map_file, err := os.Create(fn)
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }

  typ := reflect.TypeOf(RoutBtreePoolCtl{})
  n := typ.NumField()

  for i := 0; i < n; i++ {
    field := typ.Field(i)
    if field.Name == "treeRoot" {

      dataBytes := (*[32]byte)(unsafe.Pointer(&tree.ctl))
      _, err = map_file.Write(dataBytes[:field.Offset + field.Type.Size()])
    }
  }

  var node RoutBtreeNode
  for i, _ := range tree.nodes {
    dataBytes := (*[32]byte)(unsafe.Pointer(&tree.nodes[i]))
    _, err = map_file.Write(dataBytes[:unsafe.Sizeof(node)])
    if err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
  }

  map_file.Sync()

  return map_file.Close()
}

// Main
func main() {
  typ := reflect.TypeOf(RoutBtreePoolCtl{})

  fmt.Printf("Struct is %d bytes long\n", typ.Size())

  n := typ.NumField()

  for i := 0; i < n; i++ {
    field := typ.Field(i)
    fmt.Printf("%s at offset %v, size=%d, align=%d\n",
               field.Name, field.Offset, field.Type.Size(), field.Type.Align())
  }

  flag.Parse()

  count := *gParam
  fmt.Printf("Amount of the generated routing data: %d\n", count)
  tree := RoutBtree{}
  tree.Init(uint32(count))

  ch6, ch4 := GeneratorIP6NetIP4(count)

  for k:= 0; k<count; k++ {

    fmt.Printf("#%d\n", k)

    net6  := <-ch6
    addr4 := <-ch4

    tree.Insert(&net6, &addr4)

  }

  if (true) {
    //fmt.Printf("Tree.ctl: %p, %#v\n", &tree.ctl, tree.ctl)
    for r, h := range tree.nodes {
      fmt.Printf("\nTree.node[%d]: %#v", r, h)
    }
  }  

  tree.WriteToFile("file.mmap")
  fmt.Println("\n\nHopefully all written to the file.\nBye.")

}

