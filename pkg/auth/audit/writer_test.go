package audit

import (
	"encoding/json"
	"net/http"
	"testing"

	auditlogv1 "github.com/rancher/rancher/pkg/apis/auditlog.cattle.io/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type logWriter struct {
	rawLogs [][]byte
	logs    []map[string]any
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	var l map[string]any
	if err := json.Unmarshal(p, &l); err != nil {
		return 0, err
	}

	w.rawLogs = append(w.rawLogs, p)
	w.logs = append(w.logs, l)

	return len(p), nil
}

func setup(t *testing.T, opts WriterOptions) (*logWriter, *Writer) {
	lw := &logWriter{
		rawLogs: [][]byte{},
		logs:    []map[string]any{},
	}

	w, err := NewWriter(lw, opts)
	if err != nil {
		t.Fatalf("failed to create writer: %v", err)
	}

	return lw, w
}

func TestAllowList(t *testing.T) {
	logs, w := setup(t, WriterOptions{
		DefaultPolicyLevel:     auditlogv1.LevelRequestResponse,
		DisableDefaultPolicies: true,
	})

	err := w.UpdatePolicy(&auditlogv1.AuditPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "block-all",
			Namespace: "default",
		},
		Spec: auditlogv1.AuditPolicySpec{
			Filters: []auditlogv1.Filter{
				{
					Action:     auditlogv1.FilterActionDeny,
					RequestURI: ".*",
				},
			},
		},
	})
	assert.NoError(t, err)

	expected := []map[string]any{}

	err = w.Write(&log{
		RequestURI: "/api/v1/secrets",
	})
	assert.NoError(t, err)
	assert.Equal(t, expected, logs.logs)

	err = w.UpdatePolicy(&auditlogv1.AuditPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-secrets",
			Namespace: "default",
		},
		Spec: auditlogv1.AuditPolicySpec{
			Filters: []auditlogv1.Filter{
				{
					Action:     auditlogv1.FilterActionAllow,
					RequestURI: "/api/v1/secrets",
				},
			},
		},
	})
	assert.NoError(t, err)

	expected = []map[string]any{
		{
			"requestURI": "/api/v1/secrets",
		},
	}

	err = w.Write(&log{
		RequestURI: "/api/v1/secrets",
	})
	assert.NoError(t, err)
	assert.Equal(t, expected, logs.logs)
}

func TestBlockList(t *testing.T) {
	logs, w := setup(t, WriterOptions{
		DefaultPolicyLevel:     auditlogv1.LevelRequestResponse,
		DisableDefaultPolicies: true,
	})

	expected := []map[string]any{
		{
			"requestURI": "/api/v1/secrets",
			"method":     http.MethodGet,
		},
	}

	err := w.Write(&log{
		RequestURI: "/api/v1/secrets",
		Method:     http.MethodGet,
	})
	assert.NoError(t, err)
	assert.Equal(t, expected, logs.logs)

	err = w.UpdatePolicy(&auditlogv1.AuditPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-secrets",
			Namespace: "default",
		},
		Spec: auditlogv1.AuditPolicySpec{
			Filters: []auditlogv1.Filter{
				{
					Action:     auditlogv1.FilterActionDeny,
					RequestURI: "/api/v1/secrets",
				},
			},
		},
	})
	assert.NoError(t, err)

	err = w.Write(&log{
		RequestURI: "/api/v1/secrets",
		Method:     http.MethodGet,
	})
	assert.NoError(t, err)
	assert.Equal(t, expected, logs.logs)
}

func TestHigherVerbosityForPolicy(t *testing.T) {
	bodyContent := []byte(`{"password":"password"}`)
	headers := map[string][]string{
		"foo": {"bar"},
		"baz": {"qux"},
	}
	logs, w := setup(t, WriterOptions{
		DefaultPolicyLevel:     auditlogv1.LevelNull,
		DisableDefaultPolicies: true,
	})

	w.UpdatePolicy(&auditlogv1.AuditPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "set-higher-default-verbosity",
		},
		Spec: auditlogv1.AuditPolicySpec{
			Verbosity: auditlogv1.LogVerbosity{
				Level: auditlogv1.LevelRequest,
			},
		},
	})

	w.UpdatePolicy(&auditlogv1.AuditPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "set-higher-custom-default-verbosity-for-specific-url",
		},
		Spec: auditlogv1.AuditPolicySpec{
			Filters: []auditlogv1.Filter{
				{
					Action:     auditlogv1.FilterActionAllow,
					RequestURI: "/my/endopint",
				},
			},
			Verbosity: auditlogv1.LogVerbosity{
				Level: auditlogv1.LevelRequestResponse,
			},
		},
	})

	err := w.Write(&log{
		RequestURI:     "/some/endopint",
		RequestHeader:  headers,
		ResponseHeader: headers,
		RequestBody:    bodyContent,
		ResponseBody:   bodyContent,
	})
	assert.NoError(t, err)

	err = w.Write(&log{
		RequestURI:     "/my/endopint",
		RequestHeader:  headers,
		ResponseHeader: headers,
		RequestBody:    bodyContent,
		ResponseBody:   bodyContent,
	})
	assert.NoError(t, err)

	expected := []map[string]any{
		{
			"requestURI": "/some/endopint",
			"requestHeader": map[string]any{
				"foo": []any{"bar"},
				"baz": []any{"qux"},
			},
			"responseHeader": map[string]any{
				"foo": []any{"bar"},
				"baz": []any{"qux"},
			},
			"requestBody": map[string]any{
				"password": "password",
			},
		},
		{
			"requestURI": "/my/endopint",
			"requestHeader": map[string]any{
				"foo": []any{"bar"},
				"baz": []any{"qux"},
			},
			"responseHeader": map[string]any{
				"foo": []any{"bar"},
				"baz": []any{"qux"},
			},
			"requestBody": map[string]any{
				"password": "password",
			},
			"responseBody": map[string]any{
				"password": "password",
			},
		},
	}

	assert.Equal(t, expected, logs.logs)
}

func assertFieldIsObject(t *testing.T, obj map[string]any, field string) {
	t.Helper()
	assert.IsType(t, map[string]any{}, obj[field], "field '%s' is of type '%T' not '%T'", field, obj[field], map[string]any{})
}

func TestLogBodiesNotBase64Encoded(t *testing.T) {
	logs, w := setup(t, WriterOptions{
		DefaultPolicyLevel:     auditlogv1.LevelRequestResponse,
		DisableDefaultPolicies: true,
	})

	log := log{
		RequestURI:   "/api/some/endpoint",
		RequestBody:  []byte(`{"password":"password"}`),
		ResponseBody: []byte(`{"password":"password"}`),
	}

	err := w.Write(&log)
	assert.NoError(t, err)

	var v map[string]any

	err = json.Unmarshal(logs.rawLogs[0], &v)
	assert.NoError(t, err)

	assertFieldIsObject(t, v, "requestBody")
	assertFieldIsObject(t, v, "responseBody")
}
