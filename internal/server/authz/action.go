// Package authz defines PlainQ's fixed authorization vocabulary and shared
// tenant policy evaluator.
package authz

import "github.com/marsolab/plainq/internal/server/principal"

// Action is one stable authorization operation.
type Action string

// ResourceType is one stable tenant-owned resource kind.
type ResourceType string

//nolint:gosec // These are fixed authorization action labels, not credential material.
const (
	ActionAgentCreate        Action = "agent.create"
	ActionAgentRead          Action = "agent.read"
	ActionAgentList          Action = "agent.list"
	ActionAgentStatusSet     Action = "agent.status.set"
	ActionCredentialCreate   Action = "credential.create"
	ActionCredentialList     Action = "credential.list"
	ActionCredentialRegister Action = "credential.register"
	ActionCredentialRevoke   Action = "credential.revoke"
	ActionCredentialExchange Action = "credential.exchange"
	ActionAgentSend          Action = "agent.send"
	ActionInboxReceive       Action = "agent.inbox.receive"
	ActionInboxAck           Action = "agent.inbox.ack"
	ActionInboxNack          Action = "agent.inbox.nack"
	ActionInboxExtend        Action = "agent.inbox.extend"
	ActionQueueCreate        Action = "queue.create"
	ActionQueueRead          Action = "queue.read"
	ActionQueueSend          Action = "queue.send"
	ActionQueueReceive       Action = "queue.receive"
	ActionQueueAck           Action = "queue.ack"
	ActionQueueNack          Action = "queue.nack"
	ActionQueueExtend        Action = "queue.extend"
	ActionQueuePurge         Action = "queue.purge"
	ActionQueueDelete        Action = "queue.delete"
	ActionTopicCreate        Action = "topic.create"
	ActionTopicRead          Action = "topic.read"
	ActionTopicPublish       Action = "topic.publish"
	ActionTopicSubscribe     Action = "topic.subscribe"
	ActionTopicDelete        Action = "topic.delete"
	ActionSubscriptionRead   Action = "subscription.read"
	ActionSubscriptionList   Action = "subscription.list"
	ActionSubscriptionDelete Action = "subscription.delete"
	ActionSubscriptionSeek   Action = "subscription.seek"
	ActionSubscriptionPull   Action = "subscription.pull"
	ActionSubscriptionListen Action = "subscription.listen"
	ActionSubscriptionAck    Action = "subscription.ack"
	ActionSubscriptionNack   Action = "subscription.nack"
	ActionSubscriptionExtend Action = "subscription.extend"
	ActionDeadLetterList     Action = "deadletter.list"
	ActionDeadLetterReplay   Action = "deadletter.replay"
	ActionGrantManage        Action = "grant.manage"
	ActionQuotaManage        Action = "quota.manage"
	ActionAuditRead          Action = "audit.read"
)

const (
	ResourceTenant       ResourceType = "tenant"
	ResourceAgent        ResourceType = "agent"
	ResourceQueue        ResourceType = "queue"
	ResourceTopic        ResourceType = "topic"
	ResourceSubscription ResourceType = "subscription"
)

// Resource is a tenant-scoped authorization projection. OwnerKind and OwnerID
// enable the narrowly defined self-service rules without another lookup.
type Resource struct {
	Type      ResourceType
	TenantID  string
	ID        string
	OwnerKind principal.Kind
	OwnerID   string
}

var actionResources = map[Action]map[ResourceType]struct{}{
	ActionAgentCreate:        {ResourceTenant: {}, ResourceAgent: {}},
	ActionAgentRead:          {ResourceAgent: {}},
	ActionAgentList:          {ResourceTenant: {}},
	ActionAgentStatusSet:     {ResourceAgent: {}},
	ActionCredentialCreate:   {ResourceAgent: {}},
	ActionCredentialList:     {ResourceAgent: {}},
	ActionCredentialRegister: {ResourceAgent: {}},
	ActionCredentialRevoke:   {ResourceAgent: {}},
	ActionCredentialExchange: {ResourceAgent: {}},
	ActionAgentSend:          {ResourceAgent: {}},
	ActionInboxReceive:       {ResourceAgent: {}},
	ActionInboxAck:           {ResourceAgent: {}, ResourceSubscription: {}},
	ActionInboxNack:          {ResourceAgent: {}, ResourceSubscription: {}},
	ActionInboxExtend:        {ResourceAgent: {}, ResourceSubscription: {}},
	ActionQueueCreate:        {ResourceTenant: {}},
	ActionQueueRead:          {ResourceQueue: {}, ResourceTenant: {}},
	ActionQueueSend:          {ResourceQueue: {}},
	ActionQueueReceive:       {ResourceQueue: {}},
	ActionQueueAck:           {ResourceQueue: {}},
	ActionQueueNack:          {ResourceQueue: {}},
	ActionQueueExtend:        {ResourceQueue: {}},
	ActionQueuePurge:         {ResourceQueue: {}},
	ActionQueueDelete:        {ResourceQueue: {}},
	ActionTopicCreate:        {ResourceTenant: {}},
	ActionTopicRead:          {ResourceTopic: {}, ResourceTenant: {}},
	ActionTopicPublish:       {ResourceTopic: {}},
	ActionTopicSubscribe:     {ResourceTopic: {}},
	ActionTopicDelete:        {ResourceTopic: {}},
	ActionSubscriptionRead:   {ResourceSubscription: {}},
	ActionSubscriptionList:   {ResourceTenant: {}, ResourceAgent: {}, ResourceTopic: {}},
	ActionSubscriptionDelete: {ResourceSubscription: {}},
	ActionSubscriptionSeek:   {ResourceSubscription: {}},
	ActionSubscriptionPull:   {ResourceSubscription: {}},
	ActionSubscriptionListen: {ResourceSubscription: {}},
	ActionSubscriptionAck:    {ResourceSubscription: {}},
	ActionSubscriptionNack:   {ResourceSubscription: {}},
	ActionSubscriptionExtend: {ResourceSubscription: {}},
	ActionDeadLetterList:     {ResourceAgent: {}},
	ActionDeadLetterReplay:   {ResourceAgent: {}},
	ActionGrantManage:        {ResourceTenant: {}, ResourceAgent: {}, ResourceQueue: {}, ResourceTopic: {}, ResourceSubscription: {}},
	ActionQuotaManage:        {ResourceTenant: {}},
	ActionAuditRead:          {ResourceTenant: {}, ResourceAgent: {}, ResourceQueue: {}, ResourceTopic: {}, ResourceSubscription: {}},
}

// ValidAction reports whether action belongs to the fixed public vocabulary.
func ValidAction(action Action) bool {
	_, ok := actionResources[action]

	return ok
}

// ValidResourceType reports whether kind belongs to the fixed public vocabulary.
func ValidResourceType(kind ResourceType) bool {
	switch kind {
	case ResourceTenant, ResourceAgent, ResourceQueue, ResourceTopic, ResourceSubscription:
		return true
	default:
		return false
	}
}

// ActionSupportsResource reports whether a grant action can target the given resource kind.
func ActionSupportsResource(action Action, kind ResourceType) bool {
	resources, ok := actionResources[action]
	if !ok {
		return false
	}

	_, ok = resources[kind]

	return ok
}

// Actions returns a copy of the fixed action vocabulary.
func Actions() []Action {
	actions := make([]Action, 0, len(actionResources))
	for action := range actionResources {
		actions = append(actions, action)
	}

	return actions
}
