// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment: datastore */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
)

func scenarioLock(ctx context.Context, c *datastore.Client) {
	// Scenario: one transaction, write followed by read, read doesn't see the write.
	name := "fake-lock-name-scenarioLock-" + uuid.New()
	now := time.Now()

	l1 := dsstore.NewLock(c, name)
	l2 := dsstore.NewLock(c, name)

	// 1st process tries to acquire the lock and succeeds.
	end1 := now.Add(time.Minute)

	if err := l1.Acquire(ctx, end1); err != nil {
		glog.Exitf("1st process: store.AcquireLock(...) failed: %v", err)
	}

	// Another process tries to acquire teh lock and fails.
	if err := l2.Acquire(ctx, now.Add(time.Hour)); err == nil {
		glog.Exitf("another process: store.AcquireLock(...) should fail.")
	}

	// Another process cannot release the lock hold.
	if err := l2.Release(ctx); err == nil {
		glog.Exitf("another process: store.ReleaseLock(...) shoud fail.")
	}

	// 1st process can release the lock hold using its holder id.
	if err := l1.Release(ctx); err != nil {
		glog.Exitf("1st process: store.ReleaseLock(...) failed: %v", err)
	}

	// Another process can now acquire the lock.
	if err := l2.Acquire(ctx, now.Add(time.Hour)); err != nil {
		glog.Exitf("another process: store.AcquireLock(...) failed: %v", err)
	}

	// Cleanup the lock at the end of the test.
	if err := l1.Reset(ctx); err != nil {
		glog.Exitf("store.ResetLock(...) failed: %v", err)
	}
}

func scenarioLockConcurrency(_ context.Context, c *datastore.Client) {
	// Scenario: 8 concurrent processes try to acquire a lock and exclusively increment a counter.
	name := "fake-lock-name-" + uuid.New()

	n := 8
	count := int64(0)

	// Have a timeout that gives all go routines a chance to lock and do their work.
	nctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	glog.Infof("%v concurrent processes started", n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			incCounter(nctx, c, name, i, &count)
		}()
	}
	wg.Wait()
	glog.Infof("%v concurrent processes finished", n)

	got := atomic.LoadInt64(&count)
	want := int64(n)
	if got != want {
		glog.Exitf("count = %v, want %v", got, want)
	}
}

// incCounter trys to acquire a datastore lock for 1s, then read from count, sleep for 800ms, and write read+1 to count.
func incCounter(ctx context.Context, c *datastore.Client, name string, i int, count *int64) {
	l := dsstore.NewLock(c, name)

	// Try to acquire the lock for 1s, retry every 100ms.
	for {
		select {
		case <-ctx.Done():
			glog.Warningf("process %v exiting because of timeout before incrementing the counter", i)
			return
		default:
		}
		glog.V(1).Infof("process %v trying to acquire the lock", i)
		if err := l.Acquire(ctx, time.Now().Add(time.Second)); err == nil {
			glog.V(1).Infof("process %v acquired lock", i)
			break
		}
		glog.V(1).Infof("process %v failed to acquired the lock, sleep for a bit", i)
		time.Sleep(100 * time.Millisecond)
	}

	// Read the count, sleep for 800ms, write read+1 to count.
	// This gives other process a chance to read the value of count before we update.
	// They shouldn't be able to if locking above works correctly.
	v := atomic.LoadInt64(count)
	glog.V(1).Infof("process %v read counter value %v", i, v)
	time.Sleep(800 * time.Microsecond)
	atomic.StoreInt64(count, v+1)
	glog.V(1).Infof("process %v wrote counter value %v", i, v+1)
}
