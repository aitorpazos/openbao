// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package sentinel

import (
	"context"
	"sync"
	"time"

	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Store keeps governing policies in the barrier. Reads are served from a
// small TTL cache so request-path evaluation does not hit storage on every
// request; the TTL bounds cross-node staleness (writes land on the active
// node, other nodes refresh within one TTL).
type Store struct {
	view BarrierView

	mu       sync.RWMutex
	cacheEGP map[string]*Policy
	cacheRGP map[string]*Policy
	cachedAt time.Time
	ttl      time.Duration
}

// BarrierView is the storage view the store persists through.
type BarrierView = barrier.View

const storagePrefix = "core/sentinel/"

// NewStore returns a store rooted at the given barrier view.
func NewStore(view BarrierView, ttl time.Duration) *Store {
	return &Store{view: view, ttl: ttl}
}

// Invalidate clears the cache (called on writes).
func (s *Store) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheEGP = nil
	s.cacheRGP = nil
	s.cachedAt = time.Time{}
}

// List returns all policies of the given type, keyed by name.
func (s *Store) List(ctx context.Context, t PolicyType) (map[string]*Policy, error) {
	if policies := s.getCached(t); policies != nil {
		return policies, nil
	}

	prefix := storagePrefix + t.String() + "/"
	keys, err := s.view.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	policies := make(map[string]*Policy, len(keys))
	for _, key := range keys {
		entry, err := s.view.Get(ctx, prefix+key)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		p, err := Decode(entry.Value)
		if err != nil {
			return nil, err
		}
		policies[p.Name] = p
	}

	s.setCached(t, policies)
	return policies, nil
}

// Get returns one policy, or nil when absent.
func (s *Store) Get(ctx context.Context, t PolicyType, name string) (*Policy, error) {
	policies, err := s.List(ctx, t)
	if err != nil {
		return nil, err
	}
	return policies[name], nil
}

// Put writes a policy and invalidates the cache.
func (s *Store) Put(ctx context.Context, t PolicyType, p *Policy) error {
	value, err := p.Encode()
	if err != nil {
		return err
	}
	if err := s.view.Put(ctx, &logical.StorageEntry{
		Key:   StorageKey(t, p.Name),
		Value: value,
	}); err != nil {
		return err
	}
	s.Invalidate()
	return nil
}

// Delete removes a policy and invalidates the cache. Deleting an unknown
// policy is a no-op, matching the ACL policy endpoint behavior.
func (s *Store) Delete(ctx context.Context, t PolicyType, name string) error {
	if err := s.view.Delete(ctx, StorageKey(t, name)); err != nil {
		return err
	}
	s.Invalidate()
	return nil
}

func (s *Store) getCached(t PolicyType) map[string]*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cachedAt.IsZero() || time.Since(s.cachedAt) > s.ttl {
		return nil
	}
	if t == TypeEGP {
		return s.cacheEGP
	}
	return s.cacheRGP
}

func (s *Store) setCached(t PolicyType, policies map[string]*Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t == TypeEGP {
		s.cacheEGP = policies
	} else {
		s.cacheRGP = policies
	}
	s.cachedAt = time.Now()
}
