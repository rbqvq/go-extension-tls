// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "sync"

type ExtensionState struct {
	mutex   sync.RWMutex
	storage map[any]any
}

func (es *ExtensionState) Get(key any) (value any, ok bool) {
	es.mutex.RLock()
	defer es.mutex.RUnlock()

	value, ok = es.storage[key]
	return
}

func (es *ExtensionState) Set(key, value any) {
	es.mutex.Lock()
	defer es.mutex.Unlock()

	if es.storage == nil {
		es.storage = make(map[any]any)
	}

	es.storage[key] = value
}
