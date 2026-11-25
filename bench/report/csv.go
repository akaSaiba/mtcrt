// This package writes benchmark CSV files and averages repeated timings.
package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
)

// CSV file writer.
type CSV struct {
	file *os.File
	w    *csv.Writer
}

// Creates a new CSV file writer.
func New(path string, header []string) (*CSV, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		f.Close()
		return nil, err
	}

	return &CSV{file: f, w: w}, nil
}

// Writes a row to the CSV file.
func (c *CSV) Write(row []string) error { return c.w.Write(row) }

// Flushes and closes the file.	
func (c *CSV) Close() error {
	c.w.Flush()
	if err := c.w.Error(); err != nil {
		c.file.Close()
		return err
	}

	return c.file.Close()
}

// Formats a uint64 as a decimal string.
func Uint(v uint64) string { return strconv.FormatUint(v, 10) }

// Formats an int as a decimal string.
func Int(v int) string { return strconv.Itoa(v) }

// Formats a float64 as a string with the default precision.
func Float(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Rounds a mean to a whole number. This is used for more readable output, e.g. timing columns.
func Whole(mean float64) string {
	return fmt.Sprintf("%.0f", mean)
}

// Returns the csv tags of T. T can be any struct with csv tags.
func Header[T any]() []string {
	t := reflect.TypeFor[T]()
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("csv header: %s is not a struct", t))
	}

	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("csv")
		if tag == "" {
			panic(fmt.Sprintf("csv header: %s.%s missing csv tag", t.Name(), t.Field(i).Name))
		}

		out = append(out, tag)
	}

	return out
}

// Returns the csv-tagged fields of row. T can be any struct with csv tags.
func Record[T any](row T) []string {
	v := reflect.ValueOf(row)
	t := v.Type()
	out := make([]string, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.String {
			panic(fmt.Sprintf("csv record: %s.%s must be string", t.Name(), t.Field(i).Name))
		}

		out = append(out, f.String())
	}

	return out
}
