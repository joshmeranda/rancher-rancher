package audit

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	auditlogv1 "github.com/rancher/rancher/pkg/apis/auditlog.cattle.io/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	contentEncodingGZIP = "gzip"
	contentEncodingZLib = "deflate"
)

var (
	ErrUnsupportedEncoding = fmt.Errorf("unsupported encoding")
)

type Policy struct {
	Filters   []*Filter
	Redactors []Redactor
	Verbosity auditlogv1.LogVerbosity
}

type Writer struct {
	policyMutex sync.RWMutex
	Policy      map[types.NamespacedName]Policy

	Output io.Writer
}

func NewWriter(output io.Writer, defaultPolicyLevel auditlogv1.Level) (*Writer, error) {
	w := &Writer{
		Policy: make(map[types.NamespacedName]Policy),
		Output: output,
	}

	for _, v := range DefaultPolicies() {
		v.Spec.Verbosity.Level = defaultPolicyLevel

		if err := w.UpdatePolicy(&v); err != nil {
			return nil, fmt.Errorf("failed to add default policies: %w", err)
		}
	}

	return w, nil
}

func decompressGZIP(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}

	return decompress(gz)
}

func decompressZLib(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}

	return decompress(zr)
}

func decompress(readCloser io.ReadCloser) ([]byte, error) {
	rawData, err := io.ReadAll(readCloser)
	if err != nil {
		retErr := fmt.Errorf("failed to read compressed response: %w", err)
		closeErr := readCloser.Close()
		if closeErr != nil {
			// Using %v for close error because you can currently only wrap one error.
			// The read error is more important to the caller in this instance.
			retErr = fmt.Errorf("%w; failed to close readCloser: %v", retErr, closeErr)
		}
		return nil, retErr
	}

	if err = readCloser.Close(); err != nil {
		return rawData, fmt.Errorf("failed to close reader: %w", err)
	}

	return rawData, nil
}

func (w *Writer) decompressResponse(log *log) error {
	var err error
	var compressed []byte

	switch contentType := log.ResponseHeader.Get("Content-Encoding"); contentType {
	case contentEncodingGZIP:
		compressed, err = decompressGZIP(log.ResponseBody)
	case contentEncodingZLib:
		compressed, err = decompressZLib(log.ResponseBody)
	case "", "none":
		// not encoded do nothing
	default:
		err = fmt.Errorf("%w '%s' in resopnse header", ErrUnsupportedEncoding, contentType)
	}

	if err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	log.ResponseBody = compressed

	return nil
}

func (w *Writer) Write(log *log) error {
	redactors := []Redactor{
		RedactFunc(redactSecret),
	}
	var verbosity auditlogv1.LogVerbosity

	w.policyMutex.RLock()
	for _, p := range w.Policy {
		for _, f := range p.Filters {
			if f.Allowed(log) {
				redactors = append(redactors, p.Redactors...)
				verbosity = mergeLogVerbosities(verbosity, p.Verbosity)
			}
		}
	}
	w.policyMutex.RUnlock()

	log.applyVerbosity(verbosity)

	if err := w.decompressResponse(log); err != nil {
		return fmt.Errorf("failed to decompress response: %w", err)
	}

	for _, r := range redactors {
		// todo: will cause a lot of unecessary unmarshalling, find a way to avoid unmarshalling for each redactor. Keep a marshlled and unmarshelled version of each log?
		if err := r.Redact(log); err != nil {
			return fmt.Errorf("failed to redact log: %w", err)
		}
	}

	data, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("failed to marshal log: %w", err)
	}

	var buffer bytes.Buffer
	if err := json.Compact(&buffer, data); err != nil {
		return fmt.Errorf("failed to compact log: %w", err)
	}

	if _, err := w.Output.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write log: %w", err)
	}

	return nil
}

func (w *Writer) UpdatePolicy(policy *auditlogv1.AuditLogPolicy) error {
	newPolicy := Policy{
		Filters:   make([]*Filter, len(policy.Spec.Filters)),
		Redactors: make([]Redactor, len(policy.Spec.AdditionalRedactions)),
		Verbosity: policy.Spec.Verbosity,
	}

	if newPolicy.Verbosity.Level != auditlogv1.LevelNull {
		newPolicy.Verbosity = verbosityForLevel(newPolicy.Verbosity.Level)
	}

	for i, f := range policy.Spec.Filters {
		filter, err := NewFilter(f)
		if err != nil {
			return fmt.Errorf("failed to create filter: %w", err)
		}

		newPolicy.Filters[i] = filter
	}

	for i, r := range policy.Spec.AdditionalRedactions {
		redactor, err := NewRedactor(r)
		if err != nil {
			return fmt.Errorf("failed to create redactor: %w", err)
		}

		newPolicy.Redactors[i] = redactor
	}

	name := types.NamespacedName{
		Name:      policy.Name,
		Namespace: policy.Namespace,
	}
	w.policyMutex.Lock()
	w.Policy[name] = newPolicy
	w.policyMutex.Unlock()

	return nil
}

func (w *Writer) RemovePolicy(policy *auditlogv1.AuditLogPolicy) bool {
	w.policyMutex.Lock()
	defer w.policyMutex.Unlock()

	name := types.NamespacedName{
		Name:      policy.Name,
		Namespace: policy.Namespace,
	}

	if _, ok := w.Policy[name]; ok {
		delete(w.Policy, name)
		return true
	}

	return false
}

func (l *Writer) Start(ctx context.Context) {
	if l == nil {
		return
	}

	go func() {
		<-ctx.Done()
	}()
}
