package tls

import "crypto/tls"

type compatibleConn struct {
	*Conn
}

func (c *compatibleConn) ConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState().Compatible()
}

// Convert exported ConnectionState fields.
func (c *Conn) Compatible() *compatibleConn {
	return &compatibleConn{Conn: c}
}

type fullCompatibleConn struct {
	*Conn
}

func (c *fullCompatibleConn) ConnectionState() tls.ConnectionState {
	return c.Conn.ConnectionState().FullCompatible()
}

// Convert all ConnectionState fields by reflect (unsafe).
func (c *Conn) FullCompatible() *fullCompatibleConn {
	return &fullCompatibleConn{Conn: c}
}
