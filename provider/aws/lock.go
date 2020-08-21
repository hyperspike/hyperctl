// We have a table containing some entries, for each one we need to
// lock, do some work, then unlock the entry.
//
// To illustrate a typical distributed solution we make a couple of
// competing consumers which get a list of entries and try and lock
// them to perform this work. If one of the works fails the other
// will take up the slack.
package aws

import (
	"context"
	"math/rand"
	"time"
	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/wolfeidau/dynalock/v2"
)

var (
	defaultLockValue = dynalock.LockWithBytes([]byte(`MasterInit`))
	defaultLockTtl   = dynalock.LockWithTTL(30 * time.Second)
)

func (c Client) InitLock() {

	// ensure the random is seeded and avoid not so random random
	rand.Seed(time.Now().UnixNano())

	agentStore := dynalock.New(dynamodb.New(c.Cfg), c.ClusterName(), "Agent")
	lockStore := dynalock.New(dynamodb.New(c.Cfg), c.ClusterName(), "Lock")

	agentName := "master/" + c.InstanceID()

	log.Printf("creating agent: %s", agentName)

	// create an agent entry, note if one exists this will simply update it
	err := agentStore.Put(context.Background(), agentName, dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String("MasterInit")}))
	if err != nil {
		log.Fatal(err.Error())
	}

	// create a matching worker to do some do some work like polling a service,
	// but in a way which must be syncronised across possible instances
	// of this service
	w := newWorker(c.InstanceID(), agentStore, lockStore)

	kv, err := w.agentStore.Get(context.Background(), "master/" + c.InstanceID())
	if err != nil {
		log.Fatalf("failed to get agent: %+v", err)
	}

	log.Printf("[%s] %v", w.name, kv)

	for {
		w.doWork(kv)
	}

}

type worker struct {
	name       string
	agentStore dynalock.Store
	lockStore  dynalock.Store
	totalWork  int
}

func newWorker(name string, agentStore dynalock.Store, lockStore dynalock.Store) *worker {
	return &worker{name: name, agentStore: agentStore, lockStore: lockStore}
}

// separated out each iteration to take advantage of defer and ensure it is easier to test
func (w *worker) doWork(kv *dynalock.KVPair) {
	lock, err := w.lockStore.NewLock(context.Background(), "master/"+w.name, defaultLockTtl)
	if err != nil {
		log.Fatalf("failed to create a new lock on agent: %+v", err)
	}

	log.Printf("[%s] wait for lock", w.name)

	stopChan := make(chan struct{})

	_, err = lock.Lock(context.Background(), stopChan)
	if err != nil {
		if err == dynalock.ErrLockAcquireCancelled {
			log.Println("ErrLockAcquireCancelled")
			return // we are done for this loop
		}
		log.Fatalf("failed to lock agent: %+v", err)
	}

	defer unlockFunc(lock, w.name)

	log.Printf("[%s] record locked", w.name)

	work := 5 + rand.Intn(25) // basic random work interval between 5 and 30

	time.Sleep(duration(work))

	w.totalWork += work

	log.Printf("[%s] update agent: %s", w.name, kv.Key)

	err = w.agentStore.Put(context.Background(), kv.Key, dynalock.WriteWithAttributeValue(&dynamodb.AttributeValue{S: aws.String("MasterInit")}), dynalock.WriteWithTTL(5*time.Minute))
	if err != nil {
		log.Fatalf("failed to update agent: %+v", err)
	}

	log.Printf("[%s] work done total %d", w.name, w.totalWork)
}

// this function just helps with linters which hate me when I don't handle error return values, in this case it just logs it
func unlockFunc(lock dynalock.Locker, name string) {

	err := lock.Unlock(context.Background())
	if err != nil {
		log.Printf("failed to unlock agent: %+v", err)
	}
	log.Printf("[%s] record unlocked", name)

}

func duration(n int) time.Duration {
	return time.Duration(n) * time.Second
}
