package processor

import (
	"github.com/free5gc/pcf/internal/sbi/consumer"
	"github.com/free5gc/pcf/pkg/app"
)

type Processor struct {
	app.App

	consumer *consumer.Consumer
}

type HandlerResponse struct {
	Status  int
	Headers map[string][]string
	Body    interface{}
}

func NewProcessor(pcf app.App, consumer *consumer.Consumer) (*Processor, error) {
	p := &Processor{
		App:      pcf,
		consumer: consumer,
	}

	return p, nil
}

func (p *Processor) Consumer() *consumer.Consumer {
	return p.consumer
}
