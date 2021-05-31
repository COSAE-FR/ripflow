package flow

import (
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

type Cache struct {
	Flows         *lru.Cache
	Input         chan Flow
	output        chan Flow
	idleTimeout   uint32
	activeTimeout uint32
	killSwitch    chan int
	killFlusher   chan int
	flushTicker   time.Ticker
	log           *log.Entry
	lock          sync.Mutex
}

func NewCache(maxFlows uint32, idle uint32, active uint32, output chan Flow, logger *log.Entry) (*Cache, error) {
	logger = logger.WithField("component", "cache")
	cache := Cache{
		Input:         make(chan Flow, maxFlows),
		output:        output,
		idleTimeout:   idle,
		activeTimeout: active,
		killSwitch:    make(chan int, 1),
		killFlusher:   make(chan int, 1),
		flushTicker:   *time.NewTicker(time.Duration(idle) * time.Second * 2),
		log:           logger,
	}
	lruCache, err := lru.NewWithEvict(int(maxFlows), func(key interface{}, value interface{}) {
		flow := value.(Flow)
		cache.output <- flow
	})
	cache.Flows = lruCache
	return &cache, err
}

func (c *Cache) Listen() {
	for {
		select {
		case <-c.killSwitch:
			c.log.Info("Received a listener kill switch")
			return
		case flow := <-c.Input:
			func() {
				c.lock.Lock()
				defer c.lock.Unlock()
				c.UpdateFlow(flow)
			}()

		}
	}
}

func (c *Cache) Start() error {
	go c.Listen()
	go c.flushOldest()
	return nil
}

func (c *Cache) Stop() error {
	c.killSwitch <- 1
	c.killFlusher <- 1
	cacheLength := c.Flows.Len()
	if cacheLength > 0 {
		c.log.Debugf("Flushing %d entries in cache", c.Flows.Len())
		func() {
			c.lock.Lock()
			defer c.lock.Unlock()
			c.Flows.Purge()
		}()
	}
	return nil
}

func (c *Cache) flushOldest() {
	for {
		select {
		case <-c.killFlusher:
			return
		case <-c.flushTicker.C:
			func() {
				now := time.Now()
				c.lock.Lock()
				defer c.lock.Unlock()
				for _, key := range c.Flows.Keys() {
					realKey, casted := key.(uint64)
					if !casted {
						continue
					}
					rawFlow, found := c.Flows.Peek(realKey)
					if found {
						flow, casted := rawFlow.(Flow)
						if casted {
							if uint32(flow.end.Sub(now).Seconds()) > c.idleTimeout {
								c.Flows.Remove(key)
							}
						}
					}
				}
			}()
		}
	}
}

func (c *Cache) UpdateFlow(flow Flow) {
	flowEndReason := uint8(0)
	key := flow.key.Hash()
	existing, ok := c.Flows.Get(key)
	if ok {
		existingFlow, casted := existing.(Flow)
		if casted {
			existingFlow.packetDeltaCount++
			existingFlow.octetDeltaCount += flow.octetDeltaCount
			existingFlow.end = flow.end
			existingFlow.tcpControlBits |= flow.tcpControlBits
			if uint32(flow.end.Sub(existingFlow.end).Seconds()) > c.idleTimeout {
				flowEndReason = flowEndReasonIdleTimeout
			} else {
				if existingFlow.tcpControlBits&tcpControlBitsFIN > 0 {
					flowEndReason = flowEndReasonEndOfFlow
				} else if uint32(existingFlow.end.Sub(existingFlow.start).Seconds()) > c.activeTimeout {
					flowEndReason = flowEndReasonActiveTimeout
				}
			}
			flow = existingFlow
		}
	}
	if flowEndReason == 0 {
		c.Flows.Add(key, flow)
	} else {
		c.Flows.Remove(key)
	}
}
