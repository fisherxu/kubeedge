package channelq

import (
	"fmt"
	"strings"
	"sync"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	beehiveContext "github.com/kubeedge/beehive/pkg/core/context"
	beehiveModel "github.com/kubeedge/beehive/pkg/core/model"
	"github.com/kubeedge/kubeedge/cloud/pkg/cloudhub/common/model"
	deviceconst "github.com/kubeedge/kubeedge/cloud/pkg/devicecontroller/constants"
	edgeconst "github.com/kubeedge/kubeedge/cloud/pkg/edgecontroller/constants"
	edgemessagelayer "github.com/kubeedge/kubeedge/cloud/pkg/edgecontroller/messagelayer"
	"github.com/kubeedge/kubeedge/common/constants"
)

// ChannelMessageQueue is the channel implementation of MessageQueue
type ChannelMessageQueue struct {
	queuePool sync.Map
	storePool sync.Map
}

// NewChannelMessageQueue initializes a new ChannelMessageQueue
func NewChannelMessageQueue() *ChannelMessageQueue {
	return &ChannelMessageQueue{}
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

		nodeID, err := getNodeID(msg)
		if nodeID == "" || err != nil {
			klog.Warning("node id is not found in the message")
			continue
		}

		nodeQueue, err := q.GetNodeQueue(nodeID)
		nodeStore, err := q.GetNodeStore(nodeID)
		if err != nil {
			klog.Infof("fail to get dispatch channel for %s", nodeID)
			continue
		}

		key, _ := getMsgKey(&msg)

		nodeQueue.Add(key)
		nodeStore.Add(msg)
	}
}

// getNodeID from "beehive/pkg/core/model".Message.Router.Resource
func getNodeID(msg beehiveModel.Message) (string, error) {
	sli := strings.Split(msg.GetResource(), constants.ResourceSep)
	if len(sli) <= 1 {
		return "", fmt.Errorf("node id not found")
	}
	return sli[1], nil
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

func (q *ChannelMessageQueue) GetNodeQueue(nodeID string) (workqueue.RateLimitingInterface, error) {
	queue, ok := q.queuePool.Load(nodeID)
	if !ok {
		klog.Errorf("rChannel for edge node %s is removed", nodeID)
		return nil, fmt.Errorf("rChannel not found")
	}
	nodeQueue := queue.(workqueue.RateLimitingInterface)
	return nodeQueue, nil
}

func (q *ChannelMessageQueue) GetNodeStore(nodeID string) (cache.Store, error) {
	store, ok := q.storePool.Load(nodeID)
	if !ok {
		klog.Errorf("rChannel for edge node %s is removed", nodeID)
		return nil, fmt.Errorf("rChannel not found")
	}
	nodeStore := store.(cache.Store)
	return nodeStore, nil
}

// Connect allocates rChannel for given project and group
func (q *ChannelMessageQueue) Connect(info *model.HubInfo) error {
	_, ok := q.queuePool.Load(info.NodeID)
	if ok {
		return fmt.Errorf("edge node %s is already connected", info.NodeID)
	}

	queue := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), info.NodeID)
	store := cache.NewStore(getMsgKey)

	_, ok = q.queuePool.LoadOrStore(info.NodeID, queue)
	_, ok = q.storePool.LoadOrStore(info.NodeID, store)

	if ok {
		// rchannel is already allocated
		return fmt.Errorf("edge node %s is already connected", info.NodeID)
	}
	return nil
}

// Close closes rChannel for given project and group
func (q *ChannelMessageQueue) Close(info *model.HubInfo) error {
	_, ok := q.queuePool.Load(info.NodeID)
	if !ok {
		klog.Warningf("messageQueue for edge node %s is already removed", info.NodeID)
		return nil
	}
	q.queuePool.Delete(info.NodeID)
	q.storePool.Delete(info.NodeID)
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

// Workload returns the number of queue channels connected to queue
func (q *ChannelMessageQueue) Workload() (float64, error) {
	return 1, nil
}
