package notify

import (
	"sync"
	"testing"
	"time"
)

func TestHubWatchDoesNotMissNotificationAfterRegistration(t *testing.T) {
	hub := NewHub()
	watch := hub.Watch("agent:tenant-a:agent-a", "topic:tenant-a:topic-a")
	defer watch.Close()

	hub.Notify("topic:tenant-a:topic-a")
	select {
	case <-watch.C():
	case <-time.After(time.Second):
		t.Fatal("notification was lost")
	}
}

func TestHubWatchReceivesEitherWatchedKeyOnce(t *testing.T) {
	hub := NewHub()
	watch := hub.Watch("agent:tenant-a:agent-a", "agent:tenant-a:agent-a", "topic:tenant-a:topic-a")
	defer watch.Close()

	hub.Notify("agent:tenant-a:agent-a")
	select {
	case <-watch.C():
	case <-time.After(time.Second):
		t.Fatal("notification was lost")
	}
}

func TestHubWatchCloseStopsNotifications(t *testing.T) {
	hub := NewHub()
	watch := hub.Watch("topic:tenant-a:topic-a")
	watch.Close()

	hub.Notify("topic:tenant-a:topic-a")
	select {
	case <-watch.C():
		t.Fatal("closed watch received notification")
	case <-time.After(25 * time.Millisecond):
	}

	watch.Close()
}

func TestHubWatchAndNotifyAreRaceSafe(t *testing.T) {
	hub := NewHub()
	const workers = 16
	const iterations = 100

	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := "topic:tenant-a:topic-a"
			for range iterations {
				watch := hub.Watch(key)
				hub.Notify(key)
				select {
				case <-watch.C():
				case <-time.After(time.Second):
					t.Errorf("worker %d: notification was lost", worker)
				}
				watch.Close()
			}
		}()
	}
	wg.Wait()
}
