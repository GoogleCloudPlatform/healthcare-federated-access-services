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

package dsstore

import (
	"context"
	"time"

	"cloud.google.com/go/datastore" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
)

// Lock provides a distributed lock mechanism using datastore.
// Datastore doesn't provide a transaction commit time, the times used are local
// process times. Be aware of clock skew and add a small buffer to avoid
// problems.
//
// Example:
//   l := dsstore.NewLock(c, "lockname")
//   d := 10*time.Second
//
//   for {
//     // Respect the calling context.
//     select {
//     case <-ctx.Done():
//       return ctx.Err()
//     default:
//     }
//     // Try to acquire the lock.
//     if err := l.Acquire(ctx, time.Now().Add(d)); err == nil {
//       // Lock acuqired.
//       break
//     }
//     // Lock could not be acquired. Sleep for a while and retry.
//     time.Sleep(time.Second)
//   }
//
//   // [optional] Try to release the lock as soon as work is done.
//   // Note that explicit releasing of the lock is best-effort and
//   // cannot be gauranteed because of failures (e.g. crashes),
//   // if a process does not or fails to explicitly release the the lock,
//   // the lock will be automatically released after lock duration expires and
//   // will not cause a deadlock.
//   defer l.Release(ctx)
//
//   // We only hold the lock for 10s, so we have a bit less than 10s remaining.
//   ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
//   defer cancel()
//
//   // Critical section that requires mutual exclusion.
//   ...
//   ...

// Lock is the data for a lock.
type Lock struct {
	// client for accessing Datastore.
	client *datastore.Client

	// name is the name of the datastore lock object.
	name string

	// holder is the uuid for the holder of the lock.
	holder string
}

// NewLock creates a new lock object.
func NewLock(client *datastore.Client, name string) *Lock {
	return &Lock{
		client: client,
		name:   name,
		holder: uuid.New(),
	}
}

// lockKind is the datastore kind for locks.
const lockKind = "lock"

// lockData is the datastore lock entity.
type lockData struct {
	// holder is the uuid for the holder of the lock.
	Holder string
	// End is the time until which the lock is held.
	End time.Time
}

// Acquire attempts to acquire the lock until the specified time.
// Warning: The times used are local times, be careful with cross process clock skew,
// stop assuming that you hold the lock slightly before you
func (l *Lock) Acquire(ctx context.Context, end time.Time) error {
	key := datastore.NameKey(lockKind, l.name, nil)
	f := func(tx *datastore.Transaction) error {
		now := time.Now()

		lock := &lockData{}
		err := tx.Get(key, lock)
		if err != nil && err != datastore.ErrNoSuchEntity {
			return status.Errorf(codes.Internal, "reading %q failed: %v", l.name, err)
		}
		if lock.End.After(now) {
			return status.Errorf(codes.FailedPrecondition, "lock %q is reserved till %v > now = %v", l.name, lock.End, now)
		}
		lock = &lockData{Holder: l.holder, End: end}
		if _, err := tx.Put(key, lock); err != nil {
			return status.Errorf(codes.Internal, "writing lock %q failed: %v", l.name, err)
		}
		return nil
	}
	if _, err := l.client.RunInTransaction(ctx, f, datastore.MaxAttempts(1)); err != nil {
		return err
	}
	return nil
}

// Release attempts to release the holding of the named lock.
func (l *Lock) Release(ctx context.Context) error {
	key := datastore.NameKey(lockKind, l.name, nil)
	f := func(tx *datastore.Transaction) error {
		now := time.Now()

		lock := &lockData{}
		err := tx.Get(key, lock)
		if err != nil && err != datastore.ErrNoSuchEntity {
			return status.Errorf(codes.Internal, "reading lock %q failed: %v", l.name, err)
		}
		if lock.Holder != l.holder {
			return status.Errorf(codes.FailedPrecondition, "lock %q is hold by another process", l.name)
		}
		if lock.End.Before(now) {
			return status.Errorf(codes.FailedPrecondition, "lock %q hold ended at %v", l.name, lock.End)
		}
		lock = &lockData{Holder: l.holder, End: now}
		if _, err := tx.Put(key, lock); err != nil {
			return status.Errorf(codes.Internal, "writing lock %q failed: %v", l.name, err)
		}
		return nil
	}
	if _, err := l.client.RunInTransaction(ctx, f, datastore.MaxAttempts(1)); err != nil {
		return err
	}
	return nil
}

// Reset clears the information about the lock from datastore.
func (l *Lock) Reset(ctx context.Context) error {
	key := datastore.NameKey(lockKind, l.name, nil)
	f := func(tx *datastore.Transaction) error {
		if err := tx.Delete(key); err != nil {
			return status.Errorf(codes.Internal, "deleting lock %q failed: %v", l.name, err)
		}
		return nil
	}
	if _, err := l.client.RunInTransaction(ctx, f, datastore.MaxAttempts(1)); err != nil {
		return err
	}
	return nil
}
