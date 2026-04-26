package repl

import (
	"context"
	"log"
	"time"

	"github.com/aegis-c2/aegis/proto/aegispb"
)

// EventStream 管理后台 gRPC 事件流连接。
type EventStream struct {
	client  aegispb.OperatorServiceClient
	eventCh chan *aegispb.EventInfo
	stopCh  chan struct{}
}

// NewEventStream 创建事件流管理器。
func NewEventStream(client aegispb.OperatorServiceClient, bufSize int) *EventStream {
	return &EventStream{
		client:  client,
		eventCh: make(chan *aegispb.EventInfo, bufSize),
		stopCh:  make(chan struct{}),
	}
}

// Start 启动后台事件接收（断线自动重连，指数退避）。
func (es *EventStream) Start() {
	go es.run()
}

// Channel 返回事件接收通道。
func (es *EventStream) Channel() <-chan *aegispb.EventInfo {
	return es.eventCh
}

// Stop 停止事件流。
func (es *EventStream) Stop() {
	close(es.stopCh)
}

func (es *EventStream) run() {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-es.stopCh:
			return
		default:
		}

		stream, err := es.client.SubscribeEvents(context.Background(), &aegispb.SubscribeEventsRequest{})
		if err != nil {
			log.Printf("[EVENTS] connect error: %v, retrying in %v...", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// 连接成功，重置退避
		backoff = 1 * time.Second

		for {
			e, err := stream.Recv()
			if err != nil {
				log.Printf("[EVENTS] stream error: %v, reconnecting...", err)
				break
			}
			select {
			case es.eventCh <- e:
			case <-es.stopCh:
				return
			}
		}
	}
}
