package benchmarks

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"mtcrt/bench/compress"
	"mtcrt/bench/config"
	"mtcrt/bench/fixture"
	"mtcrt/bench/report"
)

// One revoked index stored as a 32-bit integer. (as per certificate indices in the MTC spec)
const indexListBytes = 4

// Fields for the storage.csv file.
type storageRow struct {
	N               string `csv:"N"`
	R               string `csv:"r"`
	RActual         string `csv:"r_actual"`
	B               string `csv:"B"`
	Placement       string `csv:"placement"`
	RawBlocks       string `csv:"raw_blocks"`
	TreeLeafHashes  string `csv:"tree_leaf_hashes"`
	RoaringPerBlock string `csv:"roaring_per_block"`
	List32Bit       string `csv:"list_32bit"`
}

// Runs the storage benchmark for each Case and writes storage.csv.
func RunStorage(cfg config.Config, cases []config.Case, progress func(string)) error {
	w, err := report.New(filepath.Join(cfg.Out, "storage.csv"), report.Header[storageRow]())
	if err != nil {
		return err
	}
	defer w.Close()

	for i, c := range cases {
		progress(fmt.Sprintf("storage configuration %d of %d", i+1, len(cases)))
		vec, revoked, err := fixture.BuildVector(c, cfg.Seed)
		if err != nil {
			return err
		}

		rActual := float64(len(revoked)) / float64(c.N)
		rawBlocks := vec.NumBlocks() * uint64(c.BlockSize) / 8
		treeLeaves := vec.NumBlocks() * uint64(sha256.Size)
		perBlock, err := compress.PerBlockRoaringSize(vec)
		if err != nil {
			return err
		}

		row := storageRow{
			N: report.Uint(c.N), R: report.Float(c.R), RActual: report.Float(rActual),
			B: report.Int(c.BlockSize), Placement: c.Placement,
			RawBlocks: report.Uint(rawBlocks), TreeLeafHashes: report.Uint(treeLeaves),
			RoaringPerBlock: report.Uint(perBlock), List32Bit: report.Uint(uint64(len(revoked)) * indexListBytes),
		}
		if err := w.Write(report.Record(row)); err != nil {
			return err
		}
	}

	return nil
}
