package cluster

import (
	"context"
	"testing"
	"time"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/maxatome/go-testdeep/td"
)

func TestStoreDeleteResultsRoundTripThroughFSM(t *testing.T) {
	ctx := context.Background()
	cluster := newTestCluster(t, 1)
	store := cluster.leader(5 * time.Second).node.Store()

	firstQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "first"})
	td.Require(t).CmpNoError(err)
	secondQueue, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "second"})
	td.Require(t).CmpNoError(err)
	firstTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "first"})
	td.Require(t).CmpNoError(err)
	secondTopic, err := store.CreateTopic(ctx, &queue.CreateTopicRequest{TopicName: "second"})
	td.Require(t).CmpNoError(err)

	firstSubscription, err := store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)
	_, err = store.Subscribe(ctx, firstTopic.TopicID, &queue.SubscribeRequest{QueueID: secondQueue.QueueId})
	td.Require(t).CmpNoError(err)
	secondSubscription, err := store.Subscribe(ctx, secondTopic.TopicID, &queue.SubscribeRequest{QueueID: firstQueue.QueueId})
	td.Require(t).CmpNoError(err)

	deletedTopic, err := store.DeleteTopic(ctx, firstTopic.TopicID)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, deletedTopic.RemovedSubscriptions, td.Len(2))
	td.Cmp(t, deletedTopic.RemovedSubscriptions[0].SubscriptionID, firstSubscription.SubscriptionID)

	deletedQueue, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: firstQueue.QueueId, Force: true})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, deletedQueue.RemovedSubscriptions, td.Len(1))
	td.Cmp(t, deletedQueue.RemovedSubscriptions[0].SubscriptionID, secondSubscription.SubscriptionID)

	store.consistency = ConsistencyStrong
	inventory, err := store.TopicInventory(ctx)
	td.Require(t).CmpNoError(err)
	td.Cmp(t, inventory.TopicsExist, int64(1))
	td.Cmp(t, inventory.SubscriptionCounts, map[string]int64{secondTopic.TopicID: 0})
}
