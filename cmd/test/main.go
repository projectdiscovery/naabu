package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"github.com/armon/go-socks5"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func main() {
	conf := &socks5.Config{
		Credentials: socks5.StaticCredentials{
			"test": "test",
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Println("dialing", network, addr)
			return net.Dial(network, addr)
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	go func() {
		if err = server.ListenAndServe("tcp", "127.0.0.1:38401"); err != nil {
			panic(err)
		}
	}()

	testFile := "test.txt"
	err = os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80",
		ScanType:  "c",
		Proxy:     "127.0.0.1:38401",
		ProxyAuth: "test:test",
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
		Timeout:    10 * time.Second,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		panic(err)
	}
	defer naabuRunner.Close()

	if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
		panic(err)
	}
	if !got {
		panic("no results found")
	}
}
