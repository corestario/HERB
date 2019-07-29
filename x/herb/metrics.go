package herb

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	Random      prometheus.Gauge
	CountRandom prometheus.Counter
}

func PrometheusMetrics() *Metrics {
	random := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "HERB",
		Subsystem: "MetricsSubsystem",
		Name:      "random",
		Help:      "output of HERB",
	})
	prometheus.MustRegister(random)
	countRandom := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "HERB",
		Subsystem: "MetricsSubsystem",
		Name:      "countRandom",
		Help:      "output of HERB",
	})
	prometheus.MustRegister(countRandom)
	return &Metrics{Random: random, CountRandom: countRandom}
}
