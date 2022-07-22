package scan

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnectVerify(t *testing.T) {
	go func() {
		// start tcp server
		l, err := net.Listen("tcp", ":17895")
		if err != nil {
			assert.Nil(t, err)
		}
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	s, err := NewScanner(&Options{})
	assert.Nil(t, err)
	wanted := []int{17895}
	got := s.ConnectVerify("localhost", []int{17895, 17896})
	assert.EqualValues(t, wanted, got)
}
