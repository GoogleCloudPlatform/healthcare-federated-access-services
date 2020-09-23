// Copyright 2020 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package rediz includes helpers to access cache. Rightnow, we only use GET and SETEX (set with expiration).
package rediz

import (
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/gomodule/redigo/redis" /* copybara-comment */
)

// Pool of redis connected clients.
type Pool struct {
	pool *redis.Pool
}

// NewPool creates the pool of redis clients. address in format: "host:port"
func NewPool(address string) *Pool {
	return &Pool{
		pool: &redis.Pool{
			// Maximum number of idle connections in the pool.
			MaxIdle:     3,
			IdleTimeout: 240 * time.Second,

			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", address)
				if err != nil {
					return nil, err
				}
				return c, err
			},

			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				_, err := c.Do("PING")
				return err
			},
		},
	}
}

// Client gets a client from the pool. Must call client.Close() after use to return the client.
func (s *Pool) Client() *Client {
	return &Client{conn: s.pool.Get()}
}

// Close the pool.
func (s *Pool) Close() error {
	return s.pool.Close()
}

// Client used to connect redis.
type Client struct {
	conn redis.Conn
}

// Get a value associated with given key in redis.
func (s *Client) Get(key string) ([]byte, error) {
	reply, err := s.conn.Do("GET", key)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}

	if reply == nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	return redis.Bytes(reply, err)
}

// SetWithExpiry add a key-value pair with expiry in redis.
func (s *Client) SetWithExpiry(key string, value []byte, seconds int64) error {
	_, err := redis.String(s.conn.Do("SETEX", key, seconds, value))
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	return nil
}

// Close returns the client to pool.
func (s *Client) Close() error {
	return s.conn.Close()
}
