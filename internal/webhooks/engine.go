package webhooks

import "context"

// Engine manages webhook endpoints and delivers events.
type Engine interface {
	RegisterEndpoint(ctx context.Context, req RegisterEndpointRequest) (*Endpoint, error)
	ListEndpoints(ctx context.Context) ([]Endpoint, error)
	DeleteEndpoint(ctx context.Context, id string) error
	DeliverAsync(ctx context.Context, event Event)
	ListDeliveries(ctx context.Context, endpointID string) ([]Delivery, error)
}
