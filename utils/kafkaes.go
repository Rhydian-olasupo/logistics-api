package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func InitKafkaES() {
	// Initialize Kafka and Elasticsearch connections
	// This function sets up a Kafka consumer that reads log messages and pushes them to Elasticsearch.
	// Ensure you have the necessary Kafka and Elasticsearch libraries installed.
	// You can use the segmentio/kafka-go for Kafka and elastic/go-elasticsearch for Elasticsearch.
	// Make sure to run a Kafka broker and an Elasticsearch instance before running this code.
	// This example assumes Kafka is running on localhost:9092 and Elasticsearch on localhost:9200.
	// Kafka setup
	kafkaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "logs",
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
	timer := time.NewTimer(batchTimeout)
	defer timer.Stop()

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
		} else {
			res.Body.Close()
			log.Printf("✅ Batch of %d logs pushed to ES", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-timer.C:
			flushBatch()
			timer.Reset(batchTimeout)
		default:
			m, err := kafkaReader.ReadMessage(context.Background())
			if err != nil {
				log.Printf("❌ Kafka read error: %v", err)
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

			batch = append(batch, logMsg)
			if len(batch) >= batchSize {
				flushBatch()
				timer.Reset(batchTimeout)
			}
		}
	}
}
