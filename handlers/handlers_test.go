package handlers

import (
	"net/http"
	"testing"
)

func TestDB_RefreshTokenHandler(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		db   *DB
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.db.RefreshTokenHandler(tt.args.w, tt.args.r)
		})
	}
}
