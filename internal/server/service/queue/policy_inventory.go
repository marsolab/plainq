package queue

import (
	"net/http"

	"github.com/marsolab/plainq/internal/server/authz"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
)

// legacyGRPCActionInventory is deliberately exhaustive. Descriptor tests make
// adding a generated method without a fixed policy action a build failure.
//
//nolint:unused // Descriptor tests consume the inventory; production does not need a second dispatch table.
var legacyGRPCActionInventory = map[string]authz.Action{
	v1.PlainQService_ListQueues_FullMethodName:    authz.ActionQueueRead,
	v1.PlainQService_DescribeQueue_FullMethodName: authz.ActionQueueRead,
	v1.PlainQService_CreateQueue_FullMethodName:   authz.ActionQueueCreate,
	v1.PlainQService_PurgeQueue_FullMethodName:    authz.ActionQueuePurge,
	v1.PlainQService_DeleteQueue_FullMethodName:   authz.ActionQueueDelete,
	v1.PlainQService_Send_FullMethodName:          authz.ActionQueueSend,
	v1.PlainQService_Receive_FullMethodName:       authz.ActionQueueReceive,
	v1.PlainQService_Delete_FullMethodName:        authz.ActionQueueAck,
	v1.PlainQService_ListTopics_FullMethodName:    authz.ActionTopicRead,
	v1.PlainQService_CreateTopic_FullMethodName:   authz.ActionTopicCreate,
	v1.PlainQService_DeleteTopic_FullMethodName:   authz.ActionTopicDelete,
	v1.PlainQService_Subscribe_FullMethodName:     authz.ActionTopicSubscribe,
	v1.PlainQService_Unsubscribe_FullMethodName:   authz.ActionSubscriptionDelete,
	v1.PlainQService_Publish_FullMethodName:       authz.ActionTopicPublish,
}

// legacyHTTPActionInventory uses the chi route pattern, not a caller-supplied
// URL, so the {id} spelling is checked at registration time and never parsed
// by authorization middleware.
//
//nolint:unused // Route-walk tests consume the inventory; production does not need a second dispatch table.
var legacyHTTPActionInventory = map[string]authz.Action{
	http.MethodPost + " /":                                                  authz.ActionQueueCreate,
	http.MethodGet + " /":                                                   authz.ActionQueueRead,
	http.MethodGet + " /{id}":                                               authz.ActionQueueRead,
	http.MethodPost + " /{id}/purge":                                        authz.ActionQueuePurge,
	http.MethodDelete + " /{id}":                                            authz.ActionQueueDelete,
	http.MethodGet + " /{id}/messages":                                      authz.ActionQueueRead,
	http.MethodPost + " /{id}/messages":                                     authz.ActionQueueSend,
	http.MethodPost + " /{id}/messages/receive":                             authz.ActionQueueReceive,
	http.MethodPost + " /{id}/messages/ack":                                 authz.ActionQueueAck,
	http.MethodGet + " /topics/":                                            authz.ActionTopicRead,
	http.MethodPost + " /topics/":                                           authz.ActionTopicCreate,
	http.MethodDelete + " /topics/{topicID}":                                authz.ActionTopicDelete,
	http.MethodPost + " /topics/{topicID}/publish":                          authz.ActionTopicPublish,
	http.MethodPost + " /topics/{topicID}/subscriptions":                    authz.ActionTopicSubscribe,
	http.MethodDelete + " /topics/{topicID}/subscriptions/{subscriptionID}": authz.ActionSubscriptionDelete,
}
