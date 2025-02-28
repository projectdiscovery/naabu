package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"

	"github.com/logrusorgru/aurora"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/internal/pdcp"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	// validation for local results file upload
	if options.AssetFileUpload != "" {
		_ = setupOptionalAssetUpload(options)
		file, err := os.Open(options.AssetFileUpload)
		if err != nil {
			gologger.Fatal().Msgf("Could not open file: %s\n", err)
		}
		defer file.Close()
		dec := json.NewDecoder(file)
		for dec.More() {
			var r runner.Result
			err := dec.Decode(&r)
			if err != nil {
				gologger.Fatal().Msgf("Could not decode jsonl file: %s\n", err)
			}
			options.OnResult(&result.HostResult{
				Host: r.Host,
				IP:   r.IP,
				Ports: []*port.Port{
					{
						Port:     r.Port,
						Protocol: protocol.ParseProtocol(r.Protocol),
						TLS:      r.TLS,
					},
				},
			})
		}
		options.OnClose()
		return
	}

	// setup optional asset upload
	_ = setupOptionalAssetUpload(options)

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			naabuRunner.ShowScanResultOnExit()
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			if options.ResumeCfg.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
				err := options.ResumeCfg.SaveResumeConfig()
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	err = naabuRunner.RunEnumeration(context.TODO())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	// on successful execution remove the resume file in case it exists
	options.ResumeCfg.CleanupResumeConfig()
	naabuRunner.Close()
}

// setupOptionalAssetUpload is used to setup optional asset upload
// this is optional and only initialized when explicitly enabled
func setupOptionalAssetUpload(opts *runner.Options) *pdcp.UploadWriter {
	var mustEnable bool
	// enable on multiple conditions
	if opts.AssetUpload || opts.AssetID != "" || opts.AssetName != "" || pdcp.EnableCloudUpload {
		mustEnable = true
	}
	a := aurora.NewAurora(!opts.NoColor)
	if !mustEnable {
		if !pdcp.HideAutoSaveMsg {
			gologger.Print().Msgf("[%s] UI Dashboard is disabled, Use -dashboard option to enable", a.BrightYellow("WRN"))
		}
		return nil
	}

	gologger.Info().Msgf("To view results in UI dashboard, visit https://cloud.projectdiscovery.io/assets upon completion.")
	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		if err != pdcpauth.ErrNoCreds && !pdcp.HideAutoSaveMsg {
			gologger.Verbose().Msgf("Could not get credentials for cloud upload: %s\n", err)
		}
		pdcpauth.CheckNValidateCredentials("naabu")
		return nil
	}
	writer, err := pdcp.NewUploadWriterCallback(context.Background(), creds)
	if err != nil {
		gologger.Error().Msgf("failed to setup UI dashboard: %s", err)
		return nil
	}
	if writer == nil {
		gologger.Error().Msgf("something went wrong, could not setup UI dashboard")
	}
	opts.OnResult = writer.GetWriterCallback()
	opts.OnClose = func() {
		writer.Close()
	}
	// add additional metadata
	if opts.AssetID != "" {
		// silently ignore
		_ = writer.SetAssetID(opts.AssetID)
	}
	if opts.AssetName != "" {
		// silently ignore
		writer.SetAssetGroupName(opts.AssetName)
	}
	if opts.TeamID != "" {
		writer.SetTeamID(opts.TeamID)
	}
	return writer
}
