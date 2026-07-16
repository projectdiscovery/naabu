package runner

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/stretchr/testify/require"
)

func TestHasUDPPorts(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want bool
	}{
		{name: "empty", opts: Options{}, want: false},
		{name: "tcp only", opts: Options{Ports: "80,443"}, want: false},
		{name: "udp inline", opts: Options{Ports: "u:53"}, want: true},
		{name: "mixed", opts: Options{Ports: "80,u:53,443"}, want: true},
		{name: "ports file udp", opts: Options{PortsFile: []string{"80", "u:123"}}, want: true},
		{name: "ports file tcp", opts: Options{PortsFile: []string{"80", "443"}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.opts.hasUDPPorts())
		})
	}
}

type captureWriter struct {
	buf *bytes.Buffer
}

func (w captureWriter) Write(data []byte, _ levels.Level) {
	_, _ = w.buf.Write(data)
}

func TestConfigureOutputMakesWarningVisible(t *testing.T) {
	buf := &bytes.Buffer{}
	gologger.DefaultLogger.SetWriter(captureWriter{buf: buf})
	gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	t.Cleanup(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
	})

	// Simulate gologger package default (Info): Warning must be dropped.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.Warning().Msg("hidden-before-configure")
	require.NotContains(t, buf.String(), "hidden-before-configure")

	buf.Reset()
	(&Options{}).configureOutput()
	gologger.Warning().Msg("visible-after-configure")
	require.Contains(t, buf.String(), "visible-after-configure")

	buf.Reset()
	(&Options{Silent: true}).configureOutput()
	gologger.Warning().Msg("hidden-when-silent")
	require.NotContains(t, buf.String(), "hidden-when-silent")
}
