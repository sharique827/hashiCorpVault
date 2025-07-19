package internal

import (
	"context"
	"os"

	"github.com/go-redis/redis/v8"
)

type Cache struct {
	Client *redis.Client
}

func InitCache() (*Cache, error) {
	addr := os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT")
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	return &Cache{Client: client}, nil
}
