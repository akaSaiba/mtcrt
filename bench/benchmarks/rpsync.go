package benchmarks

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"mtcrt/bench/compress"
	"mtcrt/bench/config"
	"mtcrt/bench/fixture"
	"mtcrt/bench/report"
	"mtcrt/wire"
)

type syncMeasurements struct {
	total []time.Duration
	resp  wire.SyncResponse
}

// Fields for the rp_sync.csv file.
type rpSyncRow struct {
	Kind               string `csv:"kind"`
	N                  string `csv:"N"`
	R                  string `csv:"r"`
	RActual            string `csv:"r_actual"`
	K                  string `csv:"k"`
	B                  string `csv:"B"`
	M                  string `csv:"m"`
	T                  string `csv:"t"`
	Placement          string `csv:"placement"`
	BlocksSent         string `csv:"blocks_sent"`
	BytesHeader        string `csv:"bytes_header"`
	BytesBlocks        string `csv:"bytes_blocks"`
	BytesBlocksRoaring string `csv:"bytes_blocks_roaring"`
	BytesAuth          string `csv:"bytes_auth"`
	BytesTotal         string `csv:"bytes_total"`
	BytesRNListing     string `csv:"bytes_rn_listing"`
	TApplyTotalAverage string `csv:"t_apply_total_average"`
}

// Runs full and incremental sync and writes rp_sync.csv.
func RunRPSync(cfg config.Config, cases []config.Case, progress func(string)) error {
	w, err := report.New(filepath.Join(cfg.Out, "rp_sync.csv"), report.Header[rpSyncRow]())
	if err != nil {
		return err
	}
	defer w.Close()

	done, err := runFullSync(cfg, cases, w, progress)
	if err != nil {
		return err
	}

	return runIncrementalSync(cfg, cases, w, progress, done)
}

// Runs full sync for each Case.
func runFullSync(cfg config.Config, cases []config.Case, w *report.CSV, progress func(string)) (int, error) {
	done := 0
	for _, c := range cases {
		if c.Kind != "full" {
			continue
		}

		done++
		progress(fmt.Sprintf("rp-sync configuration %d of %d", done, len(cases)))
		f, err := fixture.New(c, cfg.Seed)
		if err != nil {
			return done, err
		}

		m, err := measureSync(cfg, f, wire.SyncRequest{}, nil)
		if err == nil {
			err = writeSyncRow(w, c, f.RActual(), len(f.Revoked), m)
		}

		f.Close()
		if err != nil {
			return done, err
		}
	}

	return done, nil
}

// Runs incremental sync for each Case.
func runIncrementalSync(cfg config.Config, cases []config.Case, w *report.CSV, progress func(string), done int) error {
	groups := make(map[string][]config.Case)
	var order []string
	for _, c := range cases {
		if c.Kind != "incremental" {
			continue
		}

		key := fmt.Sprintf("%d/%g/%d/%d/%d/%s", c.N, c.R, c.K, c.BlockSize, c.T, c.Placement)
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], c)
	}

	for _, key := range order {
		group := groups[key]
		slices.SortFunc(group, func(a, b config.Case) int { return a.M - b.M })
		base := group[0]
		f, err := fixture.New(base, cfg.Seed)
		if err != nil {
			return err
		}

		full := f.Net.CA.Distributor().Serve(wire.SyncRequest{})
		lastP := full.State.P
		epochs := 0
		var measured []uint64
		for _, c := range group {
			done++
			progress(fmt.Sprintf("rp-sync configuration %d of %d", done, len(cases)))
			if epochs > 0 && f.Drifted() {
				f.Close()
				f, err = fixture.New(base, cfg.Seed)
				if err != nil {
					return err
				}

				full = f.Net.CA.Distributor().Serve(wire.SyncRequest{})
				lastP = full.State.P
				epochs = 0
				measured = nil
			}

			for epochs < c.M {
				_, added, err := f.AddEpoch(c.K)
				if err != nil {
					f.Close()
					return err
				}

				measured = append(measured, added...)
				epochs++
			}

			req := wire.SyncRequest{HasState: true, LastP: lastP}
			m, err := measureSync(cfg, f, req, &full)
			if err == nil {
				err = writeSyncRow(w, c, f.RActual(), len(measured), m)
			}

			if err != nil {
				f.Close()
				return err
			}
		}
		f.Close()
	}

	return nil
}

// Measures time taken to apply sync.
func measureSync(cfg config.Config, f *fixture.Fixture, req wire.SyncRequest, full *wire.SyncResponse) (syncMeasurements, error) {
	var out syncMeasurements
	for rep := -cfg.Warmup; rep < cfg.Reps; rep++ {
		resp := f.Net.CA.Distributor().Serve(req)

		party, err := f.Net.NewRP()
		if err != nil {
			return out, err
		}
		if full != nil {
			if err := party.ApplySync(*full); err != nil {
				return out, err
			}
		}

		runtime.GC()
		if err := party.ApplySync(resp); err != nil {
			return out, err
		}

		// t_apply_total: recorded inside ApplySync (verify cosignatures, apply blocks, check block_root).
		t := party.LastTimings()
		if rep >= 0 {
			out.total = append(out.total, t.Total)
		}
		out.resp = resp
	}

	return out, nil
}

// Writes one row to the rp_sync.csv file.
func writeSyncRow(w *report.CSV, c config.Case, rActual float64, revokedCount int, m syncMeasurements) error {
	sizes := m.resp.Sizes()
	compressed, err := compress.EncodeWireBlocks(m.resp.Blocks)
	if err != nil {
		return err
	}

	row := rpSyncRow{
		Kind: c.Kind, N: report.Uint(c.N), R: report.Float(c.R), RActual: report.Float(rActual),
		K: report.Int(c.K), B: report.Int(c.BlockSize), M: report.Int(c.M), T: report.Int(c.T),
		Placement: c.Placement, BlocksSent: report.Int(len(m.resp.Blocks)),
		BytesHeader: report.Int(sizes.Header), BytesBlocks: report.Int(sizes.Blocks),
		BytesBlocksRoaring: report.Uint(compressed), BytesAuth: report.Int(sizes.Auth),
		BytesTotal: report.Int(sizes.Total()), BytesRNListing: report.Uint(uint64(revokedCount) * indexListBytes),
		TApplyTotalAverage: report.Whole(report.MeanDuration(m.total)),
	}

	return w.Write(report.Record(row))
}
