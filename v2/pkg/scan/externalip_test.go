package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWhatsMyIP(t *testing.T) {
	externalIp, err := WhatsMyIP()
	assert.Nil(t, err)
	assert.NotEmpty(t, externalIp)
}
