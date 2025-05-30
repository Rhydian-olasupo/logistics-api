package logkafka

import (
	"context"
	"time"

	"github.com/segmentio/kafka-go"
)

var kafkaWriter *kafka.Writer

func InitKafkaWriter(brokers []string, topic string) {
	kafkaWriter = kafka.NewWriter(kafka.WriterConfig{
		Brokers:  brokers,
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
		Async:    true,
	})
}

func CloseKafkaWriter() error {
	if kafkaWriter != nil {
		return kafkaWriter.Close()
	}
	return nil
}

func WriteLogToKafka(ctx context.Context, msg []byte) error {
	return kafkaWriter.WriteMessages(ctx, kafka.Message{
		Value: msg,
		Time:  time.Now(),
	})
}
