package main

import (
	"fmt"
	"github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/config"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/runner"
	"github.com/zan8in/afrog/v3/pkg/utils"
	"github.com/zan8in/gologger"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func afrogSingleScan(target string, search string) {
	if err := newScanner([]string{target}, afrog.Scanner{
		Severity: "medium, high, critical, unknown",
		Search:   search,
	}); err != nil {
		fmt.Println(err.Error())
	}
}

type Scanner config.Options

func newScanner(target []string, opt afrog.Scanner) error {

	s := &Scanner{}

	s.Target = target
	s.TargetsFile = opt.WithTargetsFile()
	s.PocFile = opt.WithPocFile()
	s.Output = opt.WithOutput()
	s.Json = opt.WithJson()
	s.JsonAll = opt.WithJsonAll()
	s.Search = opt.WithSearch()
	s.Silent = opt.WithSilent()
	s.Severity = opt.WithSeverity()
	s.Update = opt.WithUpdate()
	s.DisableUpdateCheck = opt.WithDisableUpdateCheck()
	s.MonitorTargets = opt.WithMonitorTargets()
	s.RateLimit = opt.WithRateLimit()
	s.Concurrency = opt.WithConcurrency()
	s.Retries = opt.WithRetries()
	s.MaxHostError = opt.WithMaxHostError()
	s.Timeout = opt.WithTimeout()
	s.Proxy = opt.WithProxy()
	s.MaxRespBodySize = opt.WithMaxRespBodySize()
	s.DisableOutputHtml = opt.WithDisableOutputHtml()
	s.OOBConcurrency = opt.WithOOBConcurrency()
	s.OOBRateLimit = opt.WithOOBConcurrency()
	s.Smart = opt.WithSmart()
	s.PocExecutionDurationMonitor = opt.WithPocExecutionDurationMonitor()
	s.VulnerabilityScannerBreakpoint = opt.WithVulnerabilityScannerBreakpoint()
	s.AppendPoc = opt.WithAppendPoc()
	s.ConfigFile = opt.WithConfigFile()

	options := &config.Options{
		Target:                         s.Target,
		TargetsFile:                    s.TargetsFile,
		PocFile:                        s.PocFile,
		Output:                         s.Output,
		Json:                           s.Json,
		JsonAll:                        s.JsonAll,
		Search:                         s.Search,
		Silent:                         s.Silent,
		Severity:                       s.Severity,
		Update:                         s.Update,
		DisableUpdateCheck:             s.DisableUpdateCheck,
		MonitorTargets:                 s.MonitorTargets,
		RateLimit:                      s.RateLimit,
		Concurrency:                    s.Concurrency,
		Retries:                        s.Retries,
		MaxHostError:                   s.MaxHostError,
		Timeout:                        s.Timeout,
		Proxy:                          s.Proxy,
		MaxRespBodySize:                s.MaxRespBodySize,
		DisableOutputHtml:              s.DisableOutputHtml,
		OOBRateLimit:                   s.OOBRateLimit,
		OOBConcurrency:                 s.OOBConcurrency,
		Smart:                          s.Smart,
		PocExecutionDurationMonitor:    s.PocExecutionDurationMonitor,
		VulnerabilityScannerBreakpoint: s.VulnerabilityScannerBreakpoint,
		AppendPoc:                      s.AppendPoc,
		ConfigFile:                     s.ConfigFile,
	}

	config, err := config.NewConfig(options.ConfigFile)
	if err != nil {
		gologger.Error().Msg(err.Error())
		os.Exit(0)
	}

	options.Config = config

	if err := options.VerifyOptions(); err != nil {
		return err
	}

	r, err := runner.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("Could not create runner: %s\n", err)
		os.Exit(0)
	}

	var (
		lock      = sync.Mutex{}
		starttime = time.Now()
		number    uint32
	)
	r.OnResult = func(result *result.Result) {

		if !options.Silent {
			defer func() {
				atomic.AddUint32(&options.CurrentCount, 1)
				if !options.Silent {
					fmt.Printf("\r%d%% (%d/%d), %s", int(options.CurrentCount)*100/int(options.Count), options.CurrentCount, options.Count, strings.Split(time.Since(starttime).String(), ".")[0]+"s")
					// fmt.Printf("\r%d/%d/%d%%/%s", options.CurrentCount, options.Count, int(options.CurrentCount)*100/int(options.Count), strings.Split(time.Since(starttime).String(), ".")[0]+"s")
				}
			}()
		}

		if result.IsVul {
			lock.Lock()

			atomic.AddUint32(&number, 1)
			result.PrintColorResultInfoConsole(utils.GetNumberText(int(number)))

			if !options.DisableOutputHtml {
				r.Report.SetResult(result)
				r.Report.Append(utils.GetNumberText(int(number)))
			}

			if len(options.Json) > 0 || len(options.JsonAll) > 0 {
				r.JsonReport.SetResult(result)
				r.JsonReport.Append()
			}

			if options.VulnerabilityScannerBreakpoint {
				os.Exit(0)
			}

			lock.Unlock()
		}

	}

	if err := r.Run(); err != nil {
		gologger.Error().Msgf("runner run err: %s\n", err)
		os.Exit(0)
	}

	if len(options.Json) > 0 || len(options.JsonAll) > 0 {
		if err := r.JsonReport.AppendEndOfFile(); err != nil {
			gologger.Error().Msgf("json or json-all output err: %s\n", err)
			os.Exit(0)
		}
	}

	time.Sleep(time.Second * 3)
	gologger.Print().Msg("")

	return nil
}
