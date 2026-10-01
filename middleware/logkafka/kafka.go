package logkafka

import (
	"context"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

var kafkaWriter *kafka.Writer

func InitKafkaWriter(brokers []string, topic string) {
	// FIX: kafka.NewWriter(kafka.WriterConfig{...}) is deprecated and does not create the
	// topic if it is missing, so on a fresh broker every write failed. And because the
	// writer is Async, those failures were silently discarded. Build the Writer directly,
	// allow topic auto-creation, and log failed batches via Completion.
	kafkaWriter = &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  topic,
		Balancer:               &kafka.LeastBytes{},
		Async:                  true,
		AllowAutoTopicCreation: true,
		BatchTimeout:           100 * time.Millisecond,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				log.Printf("kafka: failed to write %d log message(s): %v", len(messages), err)
			}
		},
	}
}

// CloseKafkaWriter flushes any buffered messages and closes the writer.
func CloseKafkaWriter() error {
	if kafkaWriter != nil {
		return kafkaWriter.Close()
	}
	return nil
}

func WriteLogToKafka(ctx context.Context, msg []byte) error {
	// FIX: guard against use before InitKafkaWriter (e.g. in tests), which used to panic
	if kafkaWriter == nil {
		return nil
	}
	return kafkaWriter.WriteMessages(ctx, kafka.Message{
		Value: msg,
		Time:  time.Now(),
	})
}
