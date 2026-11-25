package cosigner

import (
	"encoding/json"
	"os"

	"mtcrt/wire"
)

// SigningRecord is the persisted record of a cosigner's signature. Record is persisted in a file.
// In benchmark, a temp file is used.
type SigningRecord struct {
	LogID       []byte          `json:"log_id"`
	State       wire.EpochState `json:"state"`
	AnSize      uint64          `json:"an_size"`
	Signature   []byte          `json:"signature"`
	CASignature []byte          `json:"ca_signature"`
}

// recordStore keeps the signing record in one JSON file.
type recordStore struct {
	path string
}

// JSON file containing signing latest signing record.
type recordFile struct {
	Record *SigningRecord `json:"record"`
}

// Creates the record file.
func createRecordStore(path string) (*recordStore, error) {
	s := &recordStore{path: path}
	if err := s.write(recordFile{}); err != nil {
		return nil, err
	}

	return s, nil
}

// Replaces the stored record with a new one.
func (s *recordStore) save(rec SigningRecord) error {
	return s.write(recordFile{Record: &rec})
}

// Writes record to file.
func (s *recordStore) write(f recordFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}

	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}

	return nil
}
