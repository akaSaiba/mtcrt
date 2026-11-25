package benchmarks

import (
	"fmt"
	"path/filepath"

	"mtcrt/bench/config"
	"mtcrt/bench/fixture"
	"mtcrt/bench/report"
	"mtcrt/wire"
)

// For size calculations.
const (
	anRootBytes     = 32   // SHA-256 A_n root in the auth section
	mldsa44SigBytes = 2420 // ML-DSA-44 signature, FIPS 204
)

// Fields for the disclosure CSV file.
type disclosureRow struct {
	N             string `csv:"N"`
	R             string `csv:"r"`
	RActual       string `csv:"r_actual"`
	K             string `csv:"k"`
	B             string `csv:"B"`
	M             string `csv:"m"`
	T             string `csv:"t"`
	C             string `csv:"c"` // cosigners, t minus the CA
	Placement     string `csv:"placement"`
	BytesAuth     string `csv:"bytes_auth"`
	BytesSigs     string `csv:"bytes_sigs"`
	BytesSigFrame string `csv:"bytes_sig_framing"`
	BytesTotal    string `csv:"bytes_total"`
	AuthShare     string `csv:"auth_share"`
}

// Runs the disclosure benchmark and writes disclosure.csv.
func RunDisclosure(cfg config.Config, cases []config.Case, progress func(string)) error {
	w, err := report.New(filepath.Join(cfg.Out, "disclosure.csv"), report.Header[disclosureRow]())
	if err != nil {
		return err
	}
	defer w.Close()

	for i, c := range cases {
		progress(fmt.Sprintf("disclosure configuration %d of %d", i+1, len(cases)))
		f, err := fixture.New(c, cfg.Seed)
		if err != nil {
			return err
		}

		full := f.Net.CA.Distributor().Serve(wire.SyncRequest{})
		for range c.M {
			_, _, err := f.AddEpoch(c.K)
			if err != nil {
				f.Close()
				return err
			}
		}

		resp := f.Net.CA.Distributor().Serve(wire.SyncRequest{HasState: true, LastP: full.State.P})
		if err := writeDisclosureRow(w, c, f.RActual(), resp); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}

// Writes one disclosure row.
func writeDisclosureRow(w *report.CSV, c config.Case, rActual float64, resp wire.SyncResponse) error {
	sizes := resp.Sizes()
	sigBytes := c.T * mldsa44SigBytes
	framing := sizes.Auth - anRootBytes - sigBytes

	row := disclosureRow{
		N: report.Uint(c.N), R: report.Float(c.R), RActual: report.Float(rActual),
		K: report.Int(c.K), B: report.Int(c.BlockSize), M: report.Int(c.M), T: report.Int(c.T),
		C: report.Int(c.T - 1), Placement: c.Placement,
		BytesAuth: report.Int(sizes.Auth), BytesSigs: report.Int(sigBytes),
		BytesSigFrame: report.Int(framing), BytesTotal: report.Int(sizes.Total()),
		AuthShare: report.Float(float64(sizes.Auth) / float64(sizes.Total())),
	}

	return w.Write(report.Record(row))
}
