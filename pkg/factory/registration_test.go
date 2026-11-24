package factory_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/free5gc/pcf/pkg/factory"
)

func TestReadConfigDnnList(t *testing.T) {
	base, err := os.ReadFile("testdata/pcfcfg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, value string
		want        []string
		wantErr     bool
	}{
		{"omitted", "", []string{"free5gc", "internet"}, false},
		{"null", "null", []string{"free5gc", "internet"}, false},
		{"custom", "[corp, ims]", []string{"corp", "ims"}, false},
		{"empty list", "[]", nil, true},
		{"empty name", "['']", nil, true},
		{"whitespace", "['corp net']", nil, true},
		{"invalid second name", "[corp, '']", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := string(base)
			if tt.value != "" {
				input = strings.Replace(input, "  pcfName: PCF", "  dnnList: "+tt.value+"\n  pcfName: PCF", 1)
			}
			path := filepath.Join(t.TempDir(), "pcfcfg.yaml")
			if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := factory.ReadConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("invalid DNN list accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.GetDnnList()
			if !slices.Equal(got, tt.want) {
				t.Fatalf("DNNs = %v, want %v", got, tt.want)
			}
			got[0] = "changed"
			if !slices.Equal(cfg.GetDnnList(), tt.want) {
				t.Fatal("caller mutated configured or default DNNs")
			}
		})
	}
}
