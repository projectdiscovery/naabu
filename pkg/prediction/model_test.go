package prediction

import (
	"testing"
)

func TestPredictBasic(t *testing.T) {
	m := NewModel()
	m.Set(80, 443, 0.85)
	m.Set(80, 8080, 0.30)
	m.Set(80, 8888, 0.10)
	m.Set(22, 80, 0.70)

	preds := m.Predict([]int{80}, 0.2)
	if len(preds) != 2 {
		t.Fatalf("expected 2 predictions above 0.2, got %d: %+v", len(preds), preds)
	}
	if preds[0].Port != 443 || preds[0].Confidence != 0.85 {
		t.Errorf("first prediction should be 443@0.85, got %d@%.2f", preds[0].Port, preds[0].Confidence)
	}
	if preds[1].Port != 8080 || preds[1].Confidence != 0.30 {
		t.Errorf("second prediction should be 8080@0.30, got %d@%.2f", preds[1].Port, preds[1].Confidence)
	}
}

func TestPredictMaxAcrossPorts(t *testing.T) {
	m := NewModel()
	m.Set(80, 3306, 0.15)
	m.Set(22, 3306, 0.40)

	// With both 80 and 22 open, 3306 should use max(0.15, 0.40) = 0.40
	preds := m.Predict([]int{80, 22}, 0.2)
	found := false
	for _, p := range preds {
		if p.Port == 3306 {
			found = true
			if p.Confidence != 0.40 {
				t.Errorf("expected confidence 0.40, got %.2f", p.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected port 3306 in predictions")
	}
}

func TestPredictSkipsOpenPorts(t *testing.T) {
	m := NewModel()
	m.Set(80, 443, 0.85)
	m.Set(80, 22, 0.40)

	// 443 is already open, should not be predicted
	preds := m.Predict([]int{80, 443}, 0.2)
	for _, p := range preds {
		if p.Port == 443 || p.Port == 80 {
			t.Errorf("should not predict already-open port %d", p.Port)
		}
	}
}

func TestPredictNoResults(t *testing.T) {
	m := NewModel()
	preds := m.Predict([]int{99999}, 0.2)
	if len(preds) != 0 {
		t.Errorf("expected 0 predictions for unknown port, got %d", len(preds))
	}
}

func TestTrain(t *testing.T) {
	m := NewModel()
	hostPorts := map[string][]int{
		"1.1.1.1": {80, 443, 22},
		"2.2.2.2": {80, 443},
		"3.3.3.3": {80, 22},
		"4.4.4.4": {80},
	}
	m.Train(hostPorts)

	// P(443 | 80) = 2/4 = 0.50 (hosts 1,2 have both)
	preds := m.Predict([]int{80}, 0.0)
	var found443, found22 bool
	for _, p := range preds {
		if p.Port == 443 {
			found443 = true
			if p.Confidence != 0.5 {
				t.Errorf("P(443|80) should be 0.5, got %.4f", p.Confidence)
			}
		}
		if p.Port == 22 {
			found22 = true
			if p.Confidence != 0.5 {
				t.Errorf("P(22|80) should be 0.5, got %.4f", p.Confidence)
			}
		}
	}
	if !found443 {
		t.Error("expected port 443 in trained predictions")
	}
	if !found22 {
		t.Error("expected port 22 in trained predictions")
	}

	// P(80 | 22) = 2/2 = 1.0 (all hosts with 22 also have 80)
	preds22 := m.Predict([]int{22}, 0.0)
	for _, p := range preds22 {
		if p.Port == 80 && p.Confidence != 1.0 {
			t.Errorf("P(80|22) should be 1.0, got %.4f", p.Confidence)
		}
	}
}

func TestDefaultModel(t *testing.T) {
	m := DefaultModel()
	srcPorts, totalEntries := m.Stats()
	if srcPorts == 0 || totalEntries == 0 {
		t.Fatal("default model should have correlations")
	}

	// Basic sanity: port 80 should predict 443
	preds := m.Predict([]int{80}, 0.5)
	found := false
	for _, p := range preds {
		if p.Port == 443 {
			found = true
		}
	}
	if !found {
		t.Error("default model should predict 443 given port 80")
	}
}

func TestPrioritize(t *testing.T) {
	m := NewModel()
	m.Set(80, 443, 0.85)
	m.Set(80, 8080, 0.30)
	m.Set(22, 3306, 0.40)

	// Given ports 80 and 22 are open, rank candidates [443, 8080, 3306, 9999]
	ranked := m.Prioritize([]int{443, 8080, 3306, 9999}, []int{80, 22})
	if len(ranked) != 4 {
		t.Fatalf("expected 4 results, got %d", len(ranked))
	}
	// 443 should be first (0.85), then 3306 (0.40), then 8080 (0.30), then 9999 (0.0)
	expected := []struct {
		port int
		conf float64
	}{
		{443, 0.85},
		{3306, 0.40},
		{8080, 0.30},
		{9999, 0.0},
	}
	for i, exp := range expected {
		if ranked[i].Port != exp.port {
			t.Errorf("position %d: expected port %d, got %d", i, exp.port, ranked[i].Port)
		}
		if ranked[i].Confidence != exp.conf {
			t.Errorf("position %d: expected confidence %.2f, got %.2f", i, exp.conf, ranked[i].Confidence)
		}
	}
}

func TestPrioritizeNoOpenPorts(t *testing.T) {
	m := NewModel()
	m.Set(80, 443, 0.85)

	// No open ports, all candidates should get 0 confidence
	ranked := m.Prioritize([]int{443, 80, 22}, nil)
	for _, r := range ranked {
		if r.Confidence != 0 {
			t.Errorf("expected 0 confidence with no open ports, got %.2f for port %d", r.Confidence, r.Port)
		}
	}
}

func TestMerge(t *testing.T) {
	m1 := NewModel()
	m1.Set(80, 443, 0.50)
	m1.Set(80, 8080, 0.30)

	m2 := NewModel()
	m2.Set(80, 443, 0.90)
	m2.Set(22, 80, 0.70)

	m1.Merge(m2)

	// Should keep higher probability for 80->443
	preds := m1.Predict([]int{80}, 0.0)
	for _, p := range preds {
		if p.Port == 443 && p.Confidence != 0.90 {
			t.Errorf("merged P(443|80) should be 0.90, got %.2f", p.Confidence)
		}
	}

	// Should have new entry from m2
	preds22 := m1.Predict([]int{22}, 0.0)
	found := false
	for _, p := range preds22 {
		if p.Port == 80 {
			found = true
		}
	}
	if !found {
		t.Error("merge should include 22->80 from m2")
	}
}
