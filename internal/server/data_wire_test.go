package server

import "testing"

// wire serializes the request's parts, for a test that sends them itself.
func (q *fileRequest) wire(t *testing.T) (contentType string, body []byte) {
	t.Helper()
	rec, metaRec := q.records(t)
	return multipartOf(t, namedPart{"record", rec}, namedPart{"blob", q.blob}, namedPart{"metaRecord", metaRec}, namedPart{"meta", q.metaBl})
}

// wire serializes the request's parts, for a test that sends them itself.
func (q *revisionRequest) wire(t *testing.T) (contentType string, body []byte) {
	t.Helper()
	return multipartOf(t, namedPart{"record", q.record(t)}, namedPart{"blob", q.blob})
}
