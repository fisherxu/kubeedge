package channelq

import (
	"fmt"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"strings"
	"sync"

	"k8s.io/klog"

	beehiveContext "github.com/kubeedge/beehive/pkg/core/context"
	beehiveModel "github.com/kubeedge/beehive/pkg/core/model"
	"github.com/kubeedge/kubeedge/cloud/pkg/cloudhub/common/model"
	deviceconst "github.com/kubeedge/kubeedge/cloud/pkg/devicecontroller/constants"
	edgeconst "github.com/kubeedge/kubeedge/cloud/pkg/edgecontroller/constants"
	edgemessagelayer "github.com/kubeedge/kubeedge/cloud/pkg/edgecontroller/messagelayer"
	"github.com/kubeedge/kubeedge/common/constants"
)

// MessageSet holds a set of messages
type MessageSet interface {
	Done(string) error
	Ack() error
	Get() (string, *beehiveModel.Message, error)
	GetCurrentElement() *beehiveModel.Message
}

// ChannelMessageSet is the channel implementation of MessageSet
type ChannelMessageSet struct {
	current  beehiveModel.Message
	queue workqueue.RateLimitingInterface
	store cache.Store
}

// NewChannelMessageSet initializes a new ChannelMessageSet instance
func NewChannelMessageSet(queue workqueue.RateLimitingInterface, store cache.Store) *ChannelMessageSet {
	return &ChannelMessageSet{queue: queue, store: store}
}

// Ack acknowledges once the event is processed
func (s *ChannelMessageSet) Ack() error {
	return nil
}

// Get obtains one msg from the queue
// Get blocks until it can return an msg to be processed.
func (s *ChannelMessageSet) Get() (string, *beehiveModel.Message, error) {
	key, _ := s.queue.Get()
	skey := key.(string)
	obj, _, _ := s.store.GetByKey(skey)

	s.current = obj.(beehiveModel.Message)

	return skey, &s.current, nil
}

func (s *ChannelMessageSet) Done(key string) error {
	s.queue.Done(key);
	err := s.store.Delete(key);
	// dummy message which indicats nil message
	s.current = beehiveModel.Message{};
	return err;
}

func (s *ChannelMessageSet) GetCurrentElement() *beehiveModel.Message {
	return &s.current
}

// ChannelMessageQueue is the channel implementation of MessageQueue
type ChannelMessageQueue struct {
	edgeQueuePool sync.Map
	edgeStorePool sync.Map
	deviceQueuePool sync.Map
	deviceStorePool sync.Map
	edgeAckChans map[string]chan beehiveModel.Message
	deviceAckChans map[string]chan beehiveModel.Message
}

// NewChannelMessageQueue initializes a new ChannelMessageQueue
func NewChannelMessageQueue() *ChannelMessageQueue {
	result := &ChannelMessageQueue{}
	result.edgeAckChans = make(map[string]chan beehiveModel.Message)
	result.deviceAckChans = make(map[string]chan beehiveModel.Message)
	return result
}

func (q *ChannelMessageQueue) GetAckChannel(nodeID string, source string) chan beehiveModel.Message {
	var ackChan chan beehiveModel.Message;

	if source == model.SrcDeviceController{
		 ackChan := q.deviceAckChans[nodeID];
		 return ackChan
	}

	ackChan = q.edgeAckChans[nodeID];

	return ackChan;
}

// ACK inserts msg to the ackchannel for specific node
func (q *ChannelMessageQueue) Ack(nodeID string, msg *beehiveModel.Message, source string) {
	if source == model.SrcDeviceController{
		q.deviceAckChans[nodeID] <- (*msg);
	}

	q.edgeAckChans[nodeID] <- (*msg);
}

// DispatchMessage gets the message from the cloud, extracts the
// node id from it, gets the channel associated with the node
// and pushes the event on the channel
func (q *ChannelMessageQueue) DispatchMessage() {
	for {
		select {
		case <-beehiveContext.Done():
			klog.Warning("Cloudhub channel eventqueue dispatch message loop stoped")
			return
		default:
		}
		msg, err := beehiveContext.Receive(model.SrcCloudHub)
		if err != nil {
			klog.Info("receive not Message format message")
			continue
		}
		nodeID, err := GetNodeID(msg)
		if nodeID == "" || err != nil {
			klog.Warning("node id is not found in the message")
			continue
		}

		source, err := GetSource(msg)

		if source == "" || err != nil {
			klog.Warning("source is not found in the message")
			continue
		}

		nodeQueue, err := q.GetNodeQueue(nodeID, source)
		nodeStore, err := q.GetNodeStore(nodeID, source)

		if err != nil {
			klog.Infof("fail to get dispatch Node Queue for Node: %s, Source : %s", nodeID, source)
			continue
		}

		key, _ := getMsgKey(&msg)
		nodeQueue.Add(key)
		nodeStore.Add(msg)
	}
}

func getMsgKey(obj interface{}) (string, error) {
	msg := obj.(*beehiveModel.Message)

	if msg.GetGroup() == edgeconst.GroupResource {
		resourceType, _ := edgemessagelayer.GetResourceType(*msg)
		resourceNamespace, _ := edgemessagelayer.GetNamespace(*msg)
		resourceName, _ := edgemessagelayer.GetResourceName(*msg)
		return resourceType + "/" + resourceNamespace + "/" + resourceName, nil
	}
	if msg.GetGroup() == deviceconst.GroupTwin {
		sli := strings.Split(msg.GetResource(), constants.ResourceSep)
		resourceType := sli[len(sli)-2]
		resourceName := sli[len(sli)-1]
		return resourceType + "/" + resourceName, nil
	}
	return "", fmt.Errorf("")
}

// getNodeID from "beehive/pkg/core/model".Message.Router.Resource
func GetNodeID(msg beehiveModel.Message) (string, error) {
	resource := msg.Router.Resource
	tokens := strings.Split(resource, constants.ResourceSep)
	numOfTokens := len(tokens)
	for i, token := range tokens {
		if token == model.ResNode && i+1 < numOfTokens && tokens[i+1] != "" {
			return tokens[i+1], nil
		}
	}

	return "", fmt.Errorf("No nodeId in Message.Router.Resource: %s", resource)
}

// getSource from "beehive/pkg/core/model".Message.Router.Source
func GetSource(msg beehiveModel.Message) (string, error) {
	source := msg.Router.Source
	return source, nil
}

// Connect allocates rChannel for given project and group
func (q *ChannelMessageQueue) Connect(info *model.HubInfo) error {
	_, edgeOk := q.edgeQueuePool.Load(info.NodeID)
	_, edgeOk = q.edgeStorePool.Load(info.NodeID)
	_, deviceOk := q.deviceQueuePool.Load(info.NodeID)
	_, deviceOk = q.deviceStorePool.Load(info.NodeID)

	if edgeOk || deviceOk {
		if !edgeOk {
			newAndStore(q, info.NodeID, model.SrcEdgeController)
		}

		if !deviceOk {
			newAndStore(q, info.NodeID, model.SrcDeviceController)
		}

		return fmt.Errorf("edge node %s is already connected", info.NodeID)
	}

	// allocate a new rchannel with default buffer size
	edgeOk, _ = newAndStore(q, info.NodeID, model.SrcEdgeController)
	deviceOk,_ = newAndStore(q, info.NodeID, model.SrcDeviceController)

	if edgeOk || deviceOk {
		// Node queue is already allocated
		return fmt.Errorf("edge node %s is already connected", info.NodeID)
	}

	// buffered channel
	q.edgeAckChans[info.NodeID] = make(chan beehiveModel.Message, 1)
	q.deviceAckChans[info.NodeID] = make(chan beehiveModel.Message, 1)
	return nil
}

func newAndStore(q *ChannelMessageQueue, nodeID string, source string) (bool, error) {
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), nodeID)
	store := cache.NewStore(getMsgKey)

	if source == model.SrcEdgeController {
		_, ok := q.edgeQueuePool.LoadOrStore(nodeID, queue)
		_, ok = q.edgeStorePool.LoadOrStore(nodeID, store)
		return ok, nil
	}

	if source == model.SrcDeviceController {
		_, ok := q.deviceQueuePool.LoadOrStore(nodeID, queue)
		_, ok = q.deviceStorePool.LoadOrStore(nodeID, store)
		return ok, nil
	}

	return false, fmt.Errorf("source type must be edgecontroller or devicecontroller")
}

// Close closes queues for given node
func (q *ChannelMessageQueue) Close(info *model.HubInfo) error {
	_, edgeOk := q.edgeQueuePool.Load(info.NodeID)
	_, deviceOk := q.deviceQueuePool.Load(info.NodeID)

	if !edgeOk && !deviceOk {
		klog.Warningf("rChannel for edge node %s is already removed", info.NodeID)
		return nil
	}

	if edgeOk {
		q.edgeQueuePool.Delete(info.NodeID)
		q.edgeStorePool.Delete(info.NodeID)
		if _, ok := q.edgeAckChans[info.NodeID]; ok {
			delete(q.edgeAckChans, info.NodeID)
		}
	}

	if deviceOk {
		q.deviceQueuePool.Delete(info.NodeID)
		q.deviceStorePool.Delete(info.NodeID)
		if _, ok := q.deviceAckChans[info.NodeID]; ok {
			delete(q.deviceAckChans, info.NodeID)
		}
	}

	return nil
}

// Publish sends message via the rchannel to Edge Controller
func (q *ChannelMessageQueue) Publish(msg *beehiveModel.Message) error {
	switch msg.Router.Source {
	case model.ResTwin:
		beehiveContext.SendToGroup(model.SrcDeviceController, *msg)
	default:
		beehiveContext.SendToGroup(model.SrcEdgeController, *msg)
	}
	return nil
}

// Consume returns wrapped data structure of corresponding workqueue and cache.store for given NodeID and group
func (q *ChannelMessageQueue) Consume(nodeID string, source string) (MessageSet, error) {
	queue, err := q.GetNodeQueue(nodeID, source)
	store, err := q.GetNodeStore(nodeID, source)

	if err != nil {
		return nil, err
	}

	return NewChannelMessageSet(queue, store), nil
}

// Workload returns the number of queue channels connected to queue
func (q *ChannelMessageQueue) Workload() (float64, error) {
	return 1, nil
}

func (q *ChannelMessageQueue) GetNodeQueue(nodeID string , source string) (workqueue.RateLimitingInterface, error) {
		var queue interface{};
		var ok bool;
		if source == model.SrcEdgeController {
			queue, ok = q.edgeQueuePool.Load(nodeID)
		}

		if source == model.SrcDeviceController {
			queue, ok = q.deviceQueuePool.Load(nodeID)
		}

		if !ok {
			klog.Errorf("%s nodeQueue for edge node %s is removed", source, nodeID)
			return nil, fmt.Errorf("%s nodeQueue not found", source)
		}

		nodeQueue := queue.(workqueue.RateLimitingInterface)
		return nodeQueue, nil
}

func (q *ChannelMessageQueue) GetNodeStore(nodeID string , source string) (cache.Store, error) {
	var store interface{};
	var ok bool;

	if source == model.SrcEdgeController {
		store, ok = q.edgeStorePool.Load(nodeID)
	}

	if source == model.SrcDeviceController {
		store, ok = q.deviceStorePool.Load(nodeID)
	}

	if !ok {
		klog.Errorf("%s nodeStore for edge node %s is removed", source, nodeID)
		return nil, fmt.Errorf("%s nodeStore not found", source)
	}

	nodeStore := store.(cache.Store)
	return nodeStore, nil
}
