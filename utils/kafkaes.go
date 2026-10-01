package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/segmentio/kafka-go"
)

type LogMessage struct {
	Level     string            `json:"level"`
	Module    string            `json:"module"`
	Message   string            `json:"message"`
	TraceID   string            `json:"trace_id"`
	Env       string            `json:"env"`
	Timestamp time.Time         `json:"timestamp"`
	Extra     map[string]string `json:"extra"`
}

// InitKafkaES consumes log messages from Kafka and bulk-indexes them into Elasticsearch.
// It runs until ctx is cancelled.
//
// FIX: brokers/topic were hard-coded and the loop could never be stopped. They are now
// parameters, and cancelling ctx (on shutdown) closes the reader and flushes the last batch.
// The Elasticsearch address comes from the ELASTICSEARCH_URL env var (default
// http://localhost:9200), which elasticsearch.NewDefaultClient reads itself.
func InitKafkaES(ctx context.Context, brokers []string, topic string) {
	// Initialize Kafka and Elasticsearch connections
	// This function sets up a Kafka consumer that reads log messages and pushes them to Elasticsearch.
	// Ensure you have the necessary Kafka and Elasticsearch libraries installed.
	// You can use the segmentio/kafka-go for Kafka and elastic/go-elasticsearch for Elasticsearch.
	// Make sure to run a Kafka broker and an Elasticsearch instance before running this code.
	// This example assumes Kafka is running on localhost:9092 and Elasticsearch on localhost:9200.
	// Kafka setup
	kafkaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: "es-pusher",
	})
	defer kafkaReader.Close()

	// Elasticsearch setup
	es, err := elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatalf("Error creating Elasticsearch client: %s", err)
	}

	fmt.Println("📡 Starting Kafka → Elasticsearch pusher...")

	const batchSize = 100
	const batchTimeout = 5 * time.Second

	batch := make([]LogMessage, 0, batchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		var buf bytes.Buffer
		for _, logMsg := range batch {
			docBytes, err := json.Marshal(logMsg)
			if err != nil {
				log.Printf("❌ Marshal error: %v", err)
				continue
			}
			buf.WriteString("{\"index\":{}}\n")
			buf.Write(docBytes)
			buf.WriteString("\n")
		}
		res, err := es.Bulk(bytes.NewReader(buf.Bytes()), es.Bulk.WithIndex("logs"))
		if err != nil {
			log.Printf("❌ Bulk index error: %v", err)
		} else if res.IsError() {
			// FIX: a 4xx/5xx from Elasticsearch is not a Go error, so failed bulk
			// requests used to be reported as success.
			log.Printf("❌ Bulk index error: %s", res.String())
			res.Body.Close()
		} else {
			res.Body.Close()
			log.Printf("✅ Batch of %d logs pushed to ES", len(batch))
		}
		batch = batch[:0]
	}

	// FIX: this used to be `select { case <-timer.C: ... default: ReadMessage() }`.
	// ReadMessage blocks until a message arrives, so the select only looked at the timer
	// between messages: when traffic stopped, a partial batch sat unflushed indefinitely,
	// and the default branch made it a busy loop. Reading in its own goroutine and
	// feeding a channel lets the select wait on messages and the ticker at the same time.
	msgs := make(chan LogMessage)
	go func() {
		defer close(msgs)
		for {
			m, err := kafkaReader.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil || err == io.EOF { // shutting down or reader closed
					return
				}
				log.Printf("❌ Kafka read error: %v", err)
				time.Sleep(time.Second) // avoid spinning while the broker is unreachable
				continue
			}

			var logMsg LogMessage
			if err := json.Unmarshal(m.Value, &logMsg); err != nil {
				log.Printf("❌ JSON decode error: %v", err)
				continue
			}

			// Auto-fill timestamp if missing
			if logMsg.Timestamp.IsZero() {
				logMsg.Timestamp = time.Now()
			}
			msgs <- logMsg
		}
	}()

	for {
		select {
		case <-ticker.C:
			flushBatch()
		case logMsg, ok := <-msgs:
			if !ok {
				flushBatch()
				return
			}
			batch = append(batch, logMsg)
			if len(batch) >= batchSize {
				flushBatch()
			}
		}
	}
}
