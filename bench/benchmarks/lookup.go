package benchmarks

import (
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"mtcrt/bench/compress"
	"mtcrt/bench/config"
	"mtcrt/bench/fixture"
	"mtcrt/bench/report"
	"mtcrt/rp"
	"mtcrt/wire"
)

// lookupResult keeps each lookup result live so the compiler actually performs the lookup and doesn't just skip it.
var lookupResult bool

// Performs 1,000,000 lookups and averages the time taken.
const lookupBatch = 1_000_000

// Fields for the lookup.csv file.
type lookupRow struct {
	N               string `csv:"N"`
	R               string `csv:"r"`
	RActual         string `csv:"r_actual"`
	B               string `csv:"B"`
	Placement       string `csv:"placement"`
	TRawAverage     string `csv:"t_raw_ns_per_lookup_average"`
	TRoaringAverage string `csv:"t_roaring_per_block_ns_per_lookup_average"`
}

// Runs the lookup benchmark and writes lookup.csv.
func RunLookup(cfg config.Config, cases []config.Case, progress func(string)) error {
	w, err := report.New(filepath.Join(cfg.Out, "lookup.csv"), report.Header[lookupRow]())
	if err != nil {
		return err
	}
	defer w.Close()

	for i, c := range cases {
		progress(fmt.Sprintf("lookup configuration %d of %d", i+1, len(cases)))
		f, err := fixture.New(c, cfg.Seed)
		if err != nil {
			return err
		}

		// The fixture and the encoded blocks are built once and reused for every rep.
		resp := f.Net.CA.Distributor().Serve(wire.SyncRequest{})
		party, err := f.Net.NewRP()
		if err == nil {
			err = party.ApplySync(resp)
		}
		if err != nil {
			f.Close()
			return err
		}

		encoded := make([][]byte, (c.N+uint64(c.BlockSize)-1)/uint64(c.BlockSize))
		for _, block := range resp.Blocks {
			encoded[block.ID], err = compress.EncodeBlock(block.Content)
			if err != nil {
				f.Close()
				return err
			}
		}

		serials := make([]uint64, lookupBatch)
		rng := fixture.RNG(cfg.Seed, uint64(i)+5000)
		for j := range serials {
			serials[j] = f.Net.Serial(rng.Uint64N(c.N))
		}

		rawSamples, compressedSamples, err := timeLookups(serials, party, encoded, c.BlockSize, cfg)
		if err != nil {
			f.Close()
			return err
		}

		row := lookupRow{
			N: report.Uint(c.N), R: report.Float(c.R), RActual: report.Float(f.RActual()),
			B: report.Int(c.BlockSize), Placement: c.Placement,
			TRawAverage:     report.Whole(report.Mean(rawSamples)),
			TRoaringAverage: report.Whole(report.Mean(compressedSamples)),
		}
		if err := w.Write(report.Record(row)); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}

// Times raw lookups and compressed lookups for each Case.
func timeLookups(serials []uint64, party *rp.RP, encoded [][]byte, blockSize int, cfg config.Config) ([]float64, []float64, error) {
	var rawSamples, compressedSamples []float64
	for rep := -cfg.Warmup; rep < cfg.Reps; rep++ {
		runtime.GC()

		start := time.Now()
		for _, serial := range serials {
			lookupResult = party.Lookup(serial) == rp.Revoked
		}

		elapsed := time.Since(start)
		if rep >= 0 {
			rawSamples = append(rawSamples, float64(elapsed.Nanoseconds())/lookupBatch)
		}

		runtime.GC()

		start = time.Now()
		var err error
		for _, serial := range serials {
			_, idx := wire.SplitSerial(serial)
			block := idx / uint64(blockSize)
			offset := uint32(idx % uint64(blockSize))
			lookupResult, err = compress.BlockContains(encoded[block], offset)
			if err != nil {
				return nil, nil, err
			}
		}
		elapsed = time.Since(start)
		if rep >= 0 {
			compressedSamples = append(compressedSamples, float64(elapsed.Nanoseconds())/lookupBatch)
		}
	}

	return rawSamples, compressedSamples, nil
}
