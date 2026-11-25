package benchmarks

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"mtcrt/bench/config"
	"mtcrt/bench/fixture"
	"mtcrt/bench/report"
	"mtcrt/epoch"
)

// Variables for epoch benchmarks
type epochVariables struct {
	advance, serve, cosigner, add, publish, epochProcessing, caWork []time.Duration
	proposalBytes                                                   []float64
}

// Fields for the epoch CSV file.
type epochRow struct {
	N                       string `csv:"N"`
	R                       string `csv:"r"`
	RActual                 string `csv:"r_actual"`
	K                       string `csv:"k"`
	B                       string `csv:"B"`
	T                       string `csv:"t"`
	C                       string `csv:"c"`
	Placement               string `csv:"placement"`
	BytesProposal           string `csv:"bytes_proposal"`
	TAdvanceAverage         string `csv:"t_advance_average"`
	TServeProposalAverage   string `csv:"t_serve_proposal_average"`
	TCosignerAverage        string `csv:"t_cosigner_average"`
	TAddCosigAverage        string `csv:"t_add_cosig_average"`
	TPublishAverage         string `csv:"t_publish_average"`
	TEpochProcessingAverage string `csv:"t_epoch_processing_average"`
	TCAWorkAverage          string `csv:"t_ca_work_average"`
}

// Runs the epoch benchmark, including a growth-only epoch, and writes epoch.csv.
func RunEpoch(cfg config.Config, cases []config.Case, progress func(string)) error {
	w, err := report.New(filepath.Join(cfg.Out, "epoch.csv"), report.Header[epochRow]())
	if err != nil {
		return err
	}
	defer w.Close()

	expansionDone := make(map[string]bool)
	for i, c := range cases {
		progress(fmt.Sprintf("epoch configuration %d of %d", i+1, len(cases)))
		samples, rActual, err := measureEpochCase(cfg, c, false)
		if err != nil {
			return err
		}

		if err := writeEpochRow(w, c, c.K, rActual, samples); err != nil {
			return err
		}

		key := fmt.Sprintf("%d/%g/%d/%d/%s", c.N, c.R, c.BlockSize, c.T, c.Placement)
		if !expansionDone[key] {
			expansionDone[key] = true
			samples, rActual, err = measureEpochCase(cfg, c, true)
			if err != nil {
				return err
			}

			if err := writeEpochRow(w, c, 0, rActual, samples); err != nil {
				return err
			}
		}
	}

	return nil
}

// Runs one epoch based on Case parameters.
func measureEpochCase(cfg config.Config, c config.Case, expansion bool) (epochVariables, float64, error) {
	f, err := fixture.New(c, cfg.Seed)
	if err != nil {
		return epochVariables{}, 0, err
	}

	defer func() { _ = f.Close() }()

	var samples epochVariables
	for rep := -cfg.Warmup; rep < cfg.Reps; rep++ {
		if !expansion && f.Drifted() {
			f.Close()
			f, err = fixture.New(c, cfg.Seed+uint64(rep+cfg.Warmup+1))
			if err != nil {
				return samples, 0, err
			}
		}

		if expansion {
			f.Net.Issue(uint64(c.BlockSize))
			f.Net.Checkpoint()
		} else {
			if _, err := f.SubmitRevocations(c.K); err != nil {
				return samples, 0, err
			}
		}

		runtime.GC()
		result, err := f.Net.RunEpoch()
		if err != nil {
			return samples, 0, err
		}

		if rep < 0 {
			continue
		}

		appendEpochSample(&samples, c, result)
	}

	return samples, f.RActual(), nil
}

// Records one measured epoch.
func appendEpochSample(samples *epochVariables, c config.Case, result epoch.EpochResult) {
	var serve, cosignerTime, add time.Duration
	var proposal float64

	// Takes first element of the array since the first cosigner is the real cosigner, rest are shadows.
	if len(result.ServeTimes) > 0 {
		serve = result.ServeTimes[0]
	}

	if len(result.CosignerTimes) > 0 {
		cosignerTime = result.CosignerTimes[0]
	}

	if len(result.AddTimes) > 0 {
		add = result.AddTimes[0]
	}

	if len(result.ProposalBytes) > 0 {
		proposal = float64(result.ProposalBytes[0])
	}

	// t_epoch_processing: CA + serve + one cosigner + add + publish.
	epochProcessing := result.CATime + serve + cosignerTime + add + result.PublishTime

	// t_ca_work: CA + (t−1)×(serving each cosigner + adding their cosignature) + publish.
	caWork := result.CATime + time.Duration(c.T-1)*(serve+add) + result.PublishTime

	samples.advance = append(samples.advance, result.CATime)
	samples.serve = append(samples.serve, serve)
	samples.cosigner = append(samples.cosigner, cosignerTime)
	samples.add = append(samples.add, add)
	samples.publish = append(samples.publish, result.PublishTime)
	samples.epochProcessing = append(samples.epochProcessing, epochProcessing)
	samples.caWork = append(samples.caWork, caWork)
	samples.proposalBytes = append(samples.proposalBytes, proposal)
}

// Writes epoch row
func writeEpochRow(w *report.CSV, c config.Case, k int, rActual float64, s epochVariables) error {
	row := epochRow{
		N: report.Uint(c.N), R: report.Float(c.R), RActual: report.Float(rActual),
		K: report.Int(k), B: report.Int(c.BlockSize), T: report.Int(c.T), C: report.Int(c.T - 1),
		Placement: c.Placement, BytesProposal: report.Whole(report.Mean(s.proposalBytes)),
		TAdvanceAverage:         report.Whole(report.MeanDuration(s.advance)),
		TServeProposalAverage:   report.Whole(report.MeanDuration(s.serve)),
		TCosignerAverage:        report.Whole(report.MeanDuration(s.cosigner)),
		TAddCosigAverage:        report.Whole(report.MeanDuration(s.add)),
		TPublishAverage:         report.Whole(report.MeanDuration(s.publish)),
		TEpochProcessingAverage: report.Whole(report.MeanDuration(s.epochProcessing)),
		TCAWorkAverage:          report.Whole(report.MeanDuration(s.caWork)),
	}

	return w.Write(report.Record(row))
}
