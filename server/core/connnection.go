package core

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2021  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"sync"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/gofrs/uuid"
)

// ImplantConnection - Abstract connection to an implant
type ImplantConnection struct {
	ID               string
	Send             chan *sudosocpb.Envelope
	RespMutex        *sync.RWMutex
	Resp             map[int64]chan *sudosocpb.Envelope
	Transport        string
	RemoteAddress    string
	LastMessage      time.Time
	LastMessageMutex *sync.RWMutex
	Cleanup          func()
}

// GetLastMessage - Retrieves the last message time
func (c *ImplantConnection) GetLastMessage() time.Time {
	c.LastMessageMutex.RLock()
	defer c.LastMessageMutex.RUnlock()

	return c.LastMessage
}

// UpdateLastMessage - Updates the last message time
func (c *ImplantConnection) UpdateLastMessage() {
	c.LastMessageMutex.Lock()
	defer c.LastMessageMutex.Unlock()

	c.LastMessage = time.Now()
}

// NewImplantConnection - Creates a new implant connection
func NewImplantConnection(transport string, remoteAddress string) *ImplantConnection {
	return &ImplantConnection{
		ID:               generateImplantConnectionID(),
		Send:             make(chan *sudosocpb.Envelope),
		RespMutex:        &sync.RWMutex{},
		LastMessageMutex: &sync.RWMutex{},
		Resp:             map[int64]chan *sudosocpb.Envelope{},
		Transport:        transport,
		RemoteAddress:    remoteAddress,
		Cleanup:          func() {},
	}
}

func generateImplantConnectionID() string {
	id, _ := uuid.NewV4()
	return id.String()
}

func (c *ImplantConnection) RequestResend(data []byte) {
	c.Send <- &sudosocpb.Envelope{
		Type: sudosocpb.MsgTunnelData,
		Data: data,
	}
}
