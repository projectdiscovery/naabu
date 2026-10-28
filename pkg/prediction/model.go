package prediction

import (
	"sort"
	"sync"
)

const DefaultThreshold = 0.2

// PortPrediction is a predicted port with its confidence score.
type PortPrediction struct {
	Port       int
	Confidence float64
}

// Model holds conditional probability data: P(TargetPort | GivenPort).
// The outer key is the known open port, the inner key is the predicted port.
type Model struct {
	mu           sync.RWMutex
	correlations map[int]map[int]float64
}

// NewModel creates an empty model.
func NewModel() *Model {
	return &Model{correlations: make(map[int]map[int]float64)}
}

// Set stores P(target | given) in the model.
func (m *Model) Set(given, target int, probability float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.correlations[given]; !ok {
		m.correlations[given] = make(map[int]float64)
	}
	m.correlations[given][target] = probability
}

// SetBidirectional stores the probability in both directions.
func (m *Model) SetBidirectional(portA, portB int, probAGivenB, probBGivenA float64) {
	m.Set(portB, portA, probAGivenB)
	m.Set(portA, portB, probBGivenA)
}

// Predict returns ports likely to be open given a set of known open ports.
// For each candidate port, the maximum conditional probability across all
// known ports is used (matching GPS's approach). Results are sorted by
// descending confidence and filtered by the threshold.
func (m *Model) Predict(openPorts []int, threshold float64) []PortPrediction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	openSet := make(map[int]struct{}, len(openPorts))
	for _, p := range openPorts {
		openSet[p] = struct{}{}
	}

	// For each candidate port, track max P across all known open ports
	candidates := make(map[int]float64)
	for _, knownPort := range openPorts {
		targets, ok := m.correlations[knownPort]
		if !ok {
			continue
		}
		for targetPort, prob := range targets {
			if _, alreadyOpen := openSet[targetPort]; alreadyOpen {
				continue
			}
			if prob > candidates[targetPort] {
				candidates[targetPort] = prob
			}
		}
	}

	predictions := make([]PortPrediction, 0, len(candidates))
	for p, conf := range candidates {
		if conf >= threshold {
			predictions = append(predictions, PortPrediction{Port: p, Confidence: conf})
		}
	}

	sort.Slice(predictions, func(i, j int) bool {
		if predictions[i].Confidence != predictions[j].Confidence {
			return predictions[i].Confidence > predictions[j].Confidence
		}
		return predictions[i].Port < predictions[j].Port
	})

	return predictions
}

// Train builds correlation data from observed scan results. Each entry
// maps an IP to the set of open ports found on that host. This computes
// P(PortA | PortB) = count(hosts with both A and B) / count(hosts with B).
func (m *Model) Train(hostPorts map[string][]int) {
	// Count how many hosts have each port open
	portCount := make(map[int]int)
	// Count how many hosts have both portA and portB open
	cooccurrence := make(map[[2]int]int)

	for _, ports := range hostPorts {
		seen := make(map[int]struct{}, len(ports))
		for _, p := range ports {
			seen[p] = struct{}{}
			portCount[p]++
		}
		portList := make([]int, 0, len(seen))
		for p := range seen {
			portList = append(portList, p)
		}
		for i := 0; i < len(portList); i++ {
			for j := 0; j < len(portList); j++ {
				if i == j {
					continue
				}
				cooccurrence[[2]int{portList[i], portList[j]}]++
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for pair, count := range cooccurrence {
		given := pair[0]
		target := pair[1]
		prob := float64(count) / float64(portCount[given])
		if _, ok := m.correlations[given]; !ok {
			m.correlations[given] = make(map[int]float64)
		}
		m.correlations[given][target] = prob
	}
}

// Merge adds correlations from another model, keeping the higher
// probability when both models have data for the same pair.
// Safe against cross-merge deadlocks: the source is snapshot-copied
// before acquiring the destination lock.
func (m *Model) Merge(other *Model) {
	other.mu.RLock()
	snapshot := make(map[int]map[int]float64, len(other.correlations))
	for given, targets := range other.correlations {
		cp := make(map[int]float64, len(targets))
		for k, v := range targets {
			cp[k] = v
		}
		snapshot[given] = cp
	}
	other.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	for given, targets := range snapshot {
		if _, ok := m.correlations[given]; !ok {
			m.correlations[given] = make(map[int]float64)
		}
		for target, prob := range targets {
			if prob > m.correlations[given][target] {
				m.correlations[given][target] = prob
			}
		}
	}
}

// MergeNew adds correlations from another model only for port pairs
// that don't already exist in this model. This prevents scan-biased
// probabilities from overwriting pre-computed data-backed values.
func (m *Model) MergeNew(other *Model) {
	other.mu.RLock()
	snapshot := make(map[int]map[int]float64, len(other.correlations))
	for given, targets := range other.correlations {
		cp := make(map[int]float64, len(targets))
		for k, v := range targets {
			cp[k] = v
		}
		snapshot[given] = cp
	}
	other.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	for given, targets := range snapshot {
		existing, hasGiven := m.correlations[given]
		if !hasGiven {
			m.correlations[given] = targets
			continue
		}
		for target, prob := range targets {
			if _, exists := existing[target]; !exists {
				existing[target] = prob
			}
		}
	}
}

// Prioritize ranks candidate ports by their likelihood of being open,
// given a set of known open ports. For each candidate, the maximum
// conditional probability across all known open ports is used.
// All candidates are returned sorted by descending priority; candidates
// with no correlation data receive a score of 0.
func (m *Model) Prioritize(candidates []int, openPorts []int) []PortPrediction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scores := make(map[int]float64, len(candidates))
	for _, candidate := range candidates {
		for _, open := range openPorts {
			if targets, ok := m.correlations[open]; ok {
				if prob, ok := targets[candidate]; ok && prob > scores[candidate] {
					scores[candidate] = prob
				}
			}
		}
	}

	predictions := make([]PortPrediction, len(candidates))
	for i, c := range candidates {
		predictions[i] = PortPrediction{Port: c, Confidence: scores[c]}
	}

	sort.Slice(predictions, func(i, j int) bool {
		if predictions[i].Confidence != predictions[j].Confidence {
			return predictions[i].Confidence > predictions[j].Confidence
		}
		return predictions[i].Port < predictions[j].Port
	})

	return predictions
}

// GetCorrelations returns all P(target | given) entries for a given port.
// The returned map is a copy safe for concurrent use.
func (m *Model) GetCorrelations(givenPort int) map[int]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	targets, ok := m.correlations[givenPort]
	if !ok {
		return nil
	}
	out := make(map[int]float64, len(targets))
	for k, v := range targets {
		out[k] = v
	}
	return out
}

// Stats returns the number of source ports and total correlation entries.
func (m *Model) Stats() (sourcePorts, totalEntries int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sourcePorts = len(m.correlations)
	for _, targets := range m.correlations {
		totalEntries += len(targets)
	}
	return
}
