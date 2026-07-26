package metrics

import "time"

// processStart is when this process came up. Uptime is derived from it rather
// than stored, so the two can never disagree.
var processStart = time.Now()

// Process-level definitions, declared up front so the catalog lists them
// before anything has registered a callback for them.
var (
	buildInfoDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_build_info",
		Help:   "Constant 1 carrying the build's version, commit and Go toolchain as labels.",
		Labels: []string{labelVersion, "commit", "go_version"},
	})

	startTimeDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_start_time_seconds",
		Help:   "Unix timestamp of when this process started.",
		Labels: []string{},
	})

	uptimeDef = define(Definition{
		Kind:   KindGauge,
		Name:   Namespace + "_uptime_seconds",
		Help:   "Seconds since this process started. A reset to near-zero is a restart nobody mentioned.",
		Labels: []string{},
	})
)

// RegisterBuildInfo publishes the build identity and process start time.
//
// The build-info series is a constant 1 whose labels carry the facts, which
// is what makes `plainq_build_info * on(instance) group_left(version) …`
// work — a dashboard can color any other series by the version that
// produced it.
func RegisterBuildInfo(version, commit, goVersion string) {
	Info(buildInfoDef, version, commit, goVersion)
	GaugeFunc(startTimeDef, func() float64 { return float64(processStart.Unix()) })
	GaugeFunc(uptimeDef, func() float64 { return time.Since(processStart).Seconds() })
}
