package controller

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// Recorder is the event surface the reconcilers use.
//
// The events/v1 API that controller-runtime now hands out takes a `related`
// object and an `action` on every call, neither of which a reconciler here
// has anything useful to say about: the object an event concerns is the one
// being reconciled, and the action is the reason. Rather than repeat two
// empty arguments at every call site, the extra parameters are filled in
// once, here.
type Recorder interface {
	// Event records a one-off event about an object.
	Event(object runtime.Object, eventtype, reason, message string)

	// Eventf records a formatted event about an object.
	Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...any)
}

// eventRecorder adapts an events/v1 recorder to the Recorder interface.
type eventRecorder struct {
	recorder events.EventRecorder
}

// NewRecorder wraps an events/v1 recorder.
func NewRecorder(recorder events.EventRecorder) Recorder {
	return eventRecorder{recorder: recorder}
}

// Event records an event, using the reason as the action. The two are the
// same thing for a controller that reports what it did rather than what it
// was asked to do.
func (r eventRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	r.recorder.Eventf(object, nil, eventtype, reason, reason, "%s", message)
}

// Eventf records a formatted event.
func (r eventRecorder) Eventf(
	object runtime.Object,
	eventtype, reason, messageFmt string,
	args ...any,
) {
	r.recorder.Eventf(object, nil, eventtype, reason, reason, messageFmt, args...)
}
