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

package gcp

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	iam "google.golang.org/api/iam/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam/api/v1"
)

const (
	BackgroundProcessDataType = "process"
	KeyGcProcessName          = "gckeys"

	kgcName           = "Key GC"
	minJitter         = 5
	maxJitter         = 30
	maxCollectionTime = 24 * 60 * 60 // 1 day
	maxExecutionTime  = 60 * 60      // 1 hour
	wakeTime          = maxExecutionTime
	progressFrequency = 10 * 60 // 10 minutes
)

type keyGcSettings struct {
	maxRequestedTTL  time.Duration
	keysPerAccount   int
	keyTTL           time.Duration
	collectFrequency time.Duration
	wakeFrequency    time.Duration
}

type KeyGarbageCollector struct {
	store storage.StorageInterface
	wh    *AccountWarehouse
	mutex *sync.Mutex
}

func NewKeyGarbageCollector(store storage.StorageInterface, wh *AccountWarehouse) (*KeyGarbageCollector, error) {
	rand.Seed(time.Now().UTC().UnixNano())
	gc := &KeyGarbageCollector{
		store: store,
		wh:    wh,
		mutex: &sync.Mutex{},
	}
	go gc.run()
	return gc, nil
}

func (gc *KeyGarbageCollector) RegisterProject(realm, project string, maxRequestedTTL time.Duration, keysPerAccount int) error {
	tx, err := gc.store.Tx(true)
	if err != nil {
		return fmt.Errorf("%s: unable to obtain storage transaction: %v", kgcName, err)
	}
	defer tx.Finish()

	kgc := &pb.BackgroundProcess{}
	locked := false
	for try := 0; try < 5; try++ {
		err := gc.store.ReadTx(BackgroundProcessDataType, storage.DefaultRealm, KeyGcProcessName, storage.LatestRev, kgc, tx)
		if err == nil || storage.ErrNotFound(err) {
			locked = true
			break
		}
		time.Sleep(time.Duration(gc.jitter() * 1e9))
	}
	if !locked {
		return fmt.Errorf("%s: unable to lock garbage collection object in data storage layer, waiting for next wake cycle", kgcName)
	}
	if kgc.ActiveProjects == nil {
		kgc.ActiveProjects = make(map[string]*pb.BackgroundProcess_Project)
	}
	if kgc.ActiveRealms == nil {
		kgc.ActiveRealms = make(map[string]*pb.BackgroundProcess_Realm)
	}
	if kgc.CleanupProjects == nil {
		kgc.CleanupProjects = make(map[string]int64)
	}
	if kgc.DroppedProjects == nil {
		kgc.DroppedProjects = make(map[string]int64)
	}
	if kgc.ProjectStatus == nil {
		kgc.ProjectStatus = make(map[string]*pb.BackgroundProcess_Status)
	}
	if kgc.SuccessStatus == nil {
		kgc.SuccessStatus = &pb.BackgroundProcess_Status{}
	}
	display := ""
	now := common.GetNowInUnix()
	emptyProject := len(project) == 0
	save := false
	if emptyProject {
		realm, ok := kgc.ActiveRealms[realm]
		if ok {
			project = realm.Project
		} else {
			return nil
		}
	}
	if emptyProject || maxRequestedTTL == 0 || keysPerAccount == 0 {
		save = true
		delete(kgc.ActiveRealms, realm)
		projRealm := gc.findRealm(kgc, project)
		if projRealm == nil {
			delete(kgc.ActiveProjects, project)
		} else {
			kgc.ActiveProjects[project] = &pb.BackgroundProcess_Project{
				Timestamp: projRealm.Timestamp,
				Params:    projRealm.Params,
			}
		}
		_, dropped := kgc.DroppedProjects[project]
		_, cleanup := kgc.CleanupProjects[project]
		if projRealm == nil && !dropped && !cleanup {
			kgc.CleanupProjects[project] = now
			display = fmt.Sprintf("%s scheduling: project %q scheduled for clean up", kgcName, project)
		}
	} else {
		numKeys := common.Max(1, keysPerAccount)
		offset := int(maxRequestedTTL.Seconds()) / numKeys
		collectSecs := common.Max(maxExecutionTime, common.Min(maxCollectionTime, offset))
		proj := &pb.BackgroundProcess_Project{
			Timestamp: now,
			Params: &pb.BackgroundProcess_Params{
				IntParams: map[string]int64{
					"maxRequestedTtl":  int64(maxRequestedTTL.Seconds()),
					"keysPerAccount":   int64(keysPerAccount),
					"keyTtl":           int64(common.KeyTTL(maxRequestedTTL, numKeys).Seconds()),
					"collectFrequency": int64(collectSecs),
				},
			},
		}
		old, ok := kgc.ActiveProjects[project]
		// TODO(cdvoisin): make merge smarter based on reviewing all realm registrations with same project.
		if !ok || !reflect.DeepEqual(old.Params, proj.Params) {
			save = true
		}
		kgc.ActiveProjects[project] = proj
		delete(kgc.CleanupProjects, project)
		delete(kgc.DroppedProjects, project)
		oldRealm, ok := kgc.ActiveRealms[realm]
		if !ok || project != oldRealm.Project || !reflect.DeepEqual(oldRealm.Params, proj.Params) {
			save = true
		}
		kgc.ActiveRealms[realm] = &pb.BackgroundProcess_Realm{
			Timestamp: now,
			Project:   project,
			Params:    proj.Params,
		}
		if oldRealm != nil && oldRealm.Project != project {
			altRealm := gc.findRealm(kgc, oldRealm.Project)
			if altRealm == nil {
				delete(kgc.ActiveProjects, oldRealm.Project)
				kgc.CleanupProjects[oldRealm.Project] = now
			} else if kgc.ActiveProjects[oldRealm.Project] != nil {
				// TODO(cdvoisin): could be smarter choice...
				op := kgc.ActiveProjects[oldRealm.Project]
				op.Timestamp = altRealm.Timestamp
				op.Params = altRealm.Params
			}
		}
		if save {
			display = fmt.Sprintf("%s registered settings: realm=%q, project=%q, maxRequestedTTL=%s, keysPerAccount=%d, collectFrequency=%s", kgcName, realm, project, common.TtlString(maxRequestedTTL), keysPerAccount, common.TtlString(time.Second*time.Duration(collectSecs)))
		}
	}

	if save {
		kgc.SettingsChangeTime = common.GetNowInUnix()
		if err := gc.store.WriteTx(BackgroundProcessDataType, storage.DefaultRealm, KeyGcProcessName, storage.LatestRev, kgc, nil, tx); err != nil {
			return fmt.Errorf("%s: unable to write garbage collection object in data storage layer: %v", kgcName, err)
		}
	}
	if len(display) > 0 {
		log.Printf(display)
	}
	return nil
}

func (gc *KeyGarbageCollector) findRealm(kgc *pb.BackgroundProcess, project string) *pb.BackgroundProcess_Realm {
	// TODO(cdvoisin): look for best fit, or merge values into new collector settings.
	for _, realm := range kgc.ActiveRealms {
		if project == realm.Project {
			return realm
		}
	}
	return nil
}

func (gc *KeyGarbageCollector) run() {
	ctx := context.Background()
	var kgc *pb.BackgroundProcess
	for sleep := gc.sleepTime(kgc, 0); true; sleep = gc.sleepTime(kgc, wakeTime) {
		// log.Printf("FIXME %s sleeping %s...", kgcName, common.TtlString(sleep))
		time.Sleep(sleep)
		lkgc, work := gc.lockGC()
		if lkgc == nil || !work {
			continue
		}
		kgc = lkgc
		if errCount := gc.garbageCollectKeys(ctx, kgc); errCount > 0 && len(kgc.SuccessStatus.Errors) > 0 {
			log.Printf("%s errors during execution: %d total errors, first error: %v", kgcName, errCount, kgc.SuccessStatus.Errors[0])
		}
		gc.finishGC(kgc)
	}
}

func (gc *KeyGarbageCollector) lockGC() (*pb.BackgroundProcess, bool) {
	tx, err := gc.store.Tx(true)
	if err != nil {
		log.Printf("%s: unable to obtain storage transaction: %v", kgcName, err)
		return nil, false
	}
	defer tx.Finish()

	kgc := &pb.BackgroundProcess{}
	locked := false
	for try := 0; try < 5; try++ {
		err := gc.store.ReadTx(BackgroundProcessDataType, storage.DefaultRealm, KeyGcProcessName, storage.LatestRev, kgc, tx)
		if err == nil || storage.ErrNotFound(err) {
			locked = true
			break
		}
		time.Sleep(time.Duration(gc.jitter() * 1e9))
	}
	if !locked {
		log.Printf("%s: unable to lock garbage collection object in data storage layer, waiting for next wake cycle", kgcName)
		return nil, false
	}
	cutoff := gc.cutoff(kgc.ActiveProjects)
	if kgc.ProgressTime >= cutoff {
		if kgc.FinishTime == 0 || kgc.SettingsChangeTime < kgc.StartTime {
			// Do not process for one of the following reasons:
			// 1. Another working already has been active recently and is likely still active.
			// 2. A worker has finished recently and the settings have not changed.
			return kgc, false
		}
	}
	kgc.ProcessName = KeyGcProcessName
	kgc.Instance = common.GenerateGUID()
	kgc.StartTime = common.GetNowInUnix()
	kgc.ProgressTime = kgc.StartTime
	kgc.FinishTime = 0
	if err := gc.store.WriteTx(BackgroundProcessDataType, storage.DefaultRealm, KeyGcProcessName, storage.LatestRev, kgc, nil, tx); err != nil {
		log.Printf("%s: unable to write garbage collection object in data storage layer: %v", kgcName, err)
		return kgc, false
	}
	log.Printf("%s start processing...", kgcName)
	return kgc, true
}

func (gc *KeyGarbageCollector) cutoff(projects map[string]*pb.BackgroundProcess_Project) int64 {
	cutoff := int64(0)
	now := common.GetNowInUnix()

	for _, v := range projects {
		freq := v.Params.IntParams["collectFrequency"]
		c := int64(now/freq) * freq
		if cutoff == 0 || c < cutoff {
			cutoff = c
		}
	}
	return cutoff
}

func (gc *KeyGarbageCollector) putGC(kgc *pb.BackgroundProcess, tries int) {
	tx, err := gc.store.Tx(true)
	if err != nil {
		log.Printf("%s: unable to obtain storage transaction: %v", kgcName, err)
		return
	}
	defer tx.Finish()

	for try := 0; try < tries; try++ {
		err = gc.store.WriteTx(BackgroundProcessDataType, storage.DefaultRealm, KeyGcProcessName, storage.LatestRev, kgc, nil, tx)
		if err == nil {
			return
		}
		time.Sleep(time.Duration(gc.jitter() * 1e9))
	}
	log.Printf("%s: unable to write garbage collection object in data storage layer: %v", kgcName, err)
}

func (gc *KeyGarbageCollector) finishGC(kgc *pb.BackgroundProcess) {
	kgc.FinishTime = common.GetNowInUnix()
	kgc.SuccessStartTime = kgc.StartTime
	kgc.SuccessFinishTime = kgc.FinishTime
	gc.putGC(kgc, 5)
}

func (gc *KeyGarbageCollector) garbageCollectKeys(ctx context.Context, kgc *pb.BackgroundProcess) int {
	maxErrors := 10
	projects := 0
	accounts := 0
	kept := 0
	rmKeys := 0
	rmAccts := 0
	cleanupProjects := 0
	errors := 0
	errTime := int64(0)
	errList := make([]*pb.BackgroundProcess_Error, 0)
	for projectName, project := range kgc.ActiveProjects {
		projects++
		pAccounts := 0
		pKept := 0
		pRmKeys := 0
		pErrors := 0
		pErrTime := int64(0)
		pErrList := make([]*pb.BackgroundProcess_Error, 0)
		if err := gc.wh.GetServiceAccounts(ctx, projectName, func(sa *iam.ServiceAccount) bool {
			if isGarbageCollectAccount(sa) {
				pAccounts++
				//log.Printf("%s processing service account: %q for user %q, %#v", kgcName, sa.Email, sa.DisplayName, sa)
				keyTTL := project.Params.IntParams["keyTtl"]
				keysPerAccount := project.Params.IntParams["keysPerAccount"]
				_, got, rm, err := gc.wh.ManageAccountKeys(ctx, projectName, sa.Email, 0, time.Duration(keyTTL)*time.Second, int(keysPerAccount))
				if err != nil {
					pErrTime = common.GetNowInUnix()
					if len(pErrList) < maxErrors {
						pErrList = append(pErrList, &pb.BackgroundProcess_Error{
							Timestamp: pErrTime,
							Text:      fmt.Errorf("manage account keys on project %q account %q: %v", project, sa.Email, err).Error(),
						})
					}
					pErrors++
				}
				pKept += got
				pRmKeys += rm
				if now := common.GetNowInUnix(); now > kgc.ProgressTime+progressFrequency {
					kgc.ProgressTime = now
					gc.putGC(kgc, 1)
				}
			}
			return true
		}); err != nil {
			pErrors++
			pErrTime = common.GetNowInUnix()
			if len(pErrList) < maxErrors {
				pErrList = append(pErrList, &pb.BackgroundProcess_Error{
					Timestamp: pErrTime,
					Text:      fmt.Errorf("warehouse get service accounts on project %q: %v", projectName, err).Error(),
				})
			}
		}
		status, ok := kgc.ProjectStatus[projectName]
		if !ok {
			status = &pb.BackgroundProcess_Status{}
			kgc.ProjectStatus[projectName] = status
		}
		if pErrTime == 0 {
			pErrTime = status.LastErrorTimestamp
		} else {
			errTime = pErrTime
		}
		populateStatus(status, pAccounts, pKept, pRmKeys, 0, 0, pErrors, pErrTime, pErrList, project.Params)
		accounts += pAccounts
		kept += pKept
		rmKeys += pRmKeys
		errors += pErrors
		if pErrTime > 0 {
			errTime = pErrTime
		}
		moreErrors := common.Min(maxErrors-len(errList), len(pErrList))
		for e := 0; e < moreErrors; e++ {
			errList = append(errList, pErrList[e])
		}
	}
	rmList := []string{}
	for projectName := range kgc.CleanupProjects {
		prevErrors := errors
		if err := gc.wh.GetServiceAccounts(ctx, projectName, func(sa *iam.ServiceAccount) bool {
			if isGarbageCollectAccount(sa) {
				if err := gc.wh.RemoveServiceAccount(ctx, projectName, sa.Email); err == nil {
					rmAccts++
				} else {
					errors++
					errTime = common.GetNowInUnix()
					if len(errList) < maxErrors {
						errList = append(errList, &pb.BackgroundProcess_Error{
							Timestamp: errTime,
							Text:      fmt.Errorf("warehouse removing service account %q on project %q: %v", sa.Email, projectName, err).Error(),
						})
					}
				}
			}
			return true
		}); err != nil && !ignoreCleanupError(err) {
			errors++
			errTime = common.GetNowInUnix()
			if len(errList) < maxErrors {
				errList = append(errList, &pb.BackgroundProcess_Error{
					Timestamp: errTime,
					Text:      fmt.Errorf("warehouse get service accounts on project %q: %v", projectName, err).Error(),
				})
			}
		}
		if prevErrors == errors {
			cleanupProjects++
			kgc.DroppedProjects[projectName] = common.GetNowInUnix()
			rmList = append(rmList, projectName)
		}
	}
	for _, projectName := range rmList {
		delete(kgc.CleanupProjects, projectName)
	}
	if kgc.SuccessStatus == nil {
		kgc.SuccessStatus = &pb.BackgroundProcess_Status{}
	}
	populateStatus(kgc.SuccessStatus, accounts, kept, rmKeys, rmAccts, cleanupProjects, errors, errTime, errList, nil)
	log.Printf("%s complete: %d active projects, %d accounts, kept %d keys, removed %d keys, removed %d accounts, cleaned up %d projects, %d errors", kgcName, projects, accounts, kept, rmKeys, rmAccts, cleanupProjects, errors)
	return errors
}

func isGarbageCollectAccount(sa *iam.ServiceAccount) bool {
	return strings.Contains(sa.DisplayName, "@") || strings.Contains(sa.DisplayName, "|")
}

func ignoreCleanupError(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Error 403") || strings.Contains(text, "Error 404")
}

func (gc *KeyGarbageCollector) sleepTime(kgc *pb.BackgroundProcess, defaultWake int) time.Duration {
	gc.mutex.Lock()
	defer gc.mutex.Unlock()

	now := common.GetNowInUnix()
	wait := float64(defaultWake)
	if kgc != nil {
		freq := time.Second * time.Duration(wait)
		ts := (int64(now/int64(freq.Seconds())) + 1) * int64(freq.Seconds())
		wait = float64(ts - now)
	}
	ns := (wait + gc.jitter()) * 1e9
	return time.Duration(ns)
}

func (gc *KeyGarbageCollector) jitter() float64 {
	return minJitter + rand.Float64()*(maxJitter-minJitter)
}

func populateStatus(status *pb.BackgroundProcess_Status, accounts, kept, rmKeys, rmAccts, cleanupProjects, errors int, errTime int64, errList []*pb.BackgroundProcess_Error, params *pb.BackgroundProcess_Params) {
	if errTime == 0 {
		errTime = status.LastErrorTimestamp
	}
	status.FinishTime = common.GetNowInUnix()
	status.LastErrorTimestamp = errTime
	status.Errors = errList
	status.Params = params

	stats := status.Stats
	if stats == nil {
		stats = make(map[string]int64)
		status.Stats = stats
	}
	stats["accounts"] = int64(accounts)
	stats["keptKeys"] = int64(kept)
	stats["removedKeys"] = int64(rmKeys)
	stats["lifetimeRemovedKeys"] += int64(rmKeys)
	stats["removedAccounts"] = int64(rmAccts)
	stats["lifetimeRemovedAccounts"] += int64(rmAccts)
	stats["cleanupProjects"] = int64(cleanupProjects)
	stats["lifetimeCleanupProjects"] += int64(cleanupProjects)
	stats["errors"] = int64(errors)
	stats["lifetimeErrors"] += int64(errors)
}
