// Command license-notices collects redistribution notices for the packages
// actually compiled into Hunter. It copies notices, never dependency source.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir, Sum string
	Main                    bool
	Replace                 *module
}

type pkg struct {
	Dir    string
	Module *module
}

type notice struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type dependency struct {
	Module  string   `json:"module"`
	Version string   `json:"version,omitempty"`
	Sum     string   `json:"sum,omitempty"`
	Files   []notice `json:"files"`
}

func main() {
	out := flag.String("out", "dist/licenses", "directory for notice files and manifest")
	flag.Parse()
	if err := collect(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func collect(out string) error {
	// Refuse to mix a previous collection with this build's dependency set.
	// The caller chooses a fresh directory; no arbitrary directory is deleted.
	if entries, err := os.ReadDir(out); err == nil && len(entries) != 0 {
		return fmt.Errorf("license output directory must be empty: %s", out)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/hunter")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("list build dependencies: %w: %s", err, stderr.String())
	}
	modules := map[string]*module{}
	dirs := map[string]map[string]bool{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var p pkg
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		m := p.Module
		if m == nil || m.Main {
			continue
		}
		modules[m.Path] = m
		if dirs[m.Path] == nil {
			dirs[m.Path] = map[string]bool{}
		}
		base := m.Dir
		if m.Replace != nil {
			base = m.Replace.Dir
		}
		if base == "" {
			return fmt.Errorf("module directory missing: %s", m.Path)
		}
		for dir := p.Dir; ; dir = filepath.Dir(dir) {
			rel, err := filepath.Rel(base, dir)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				break
			}
			dirs[m.Path][dir] = true
			if dir == base || filepath.Dir(dir) == dir {
				break
			}
		}
		dirs[m.Path][base] = true
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	var manifest []dependency
	mainDep := dependency{Module: "github.com/hkjang/hunter"}
	if err := copyNotice(root, "LICENSE", "hunter/LICENSE", out, &mainDep); err != nil {
		return err
	}
	manifest = append(manifest, mainDep)
	paths := make([]string, 0, len(modules))
	for path := range modules {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		m := modules[path]
		base := m.Dir
		if m.Replace != nil {
			base = m.Replace.Dir
		}
		d := dependency{Module: m.Path, Version: m.Version, Sum: m.Sum}
		prefix := filepath.Join("modules", m.Path+"@"+m.Version)
		if m.Path == "pentagi" {
			parent := filepath.Dir(base)
			for _, name := range []string{"LICENSE", "NOTICE", "EULA.md", "UPSTREAM.json", "README.hunter.md"} {
				if err := copyNotice(parent, name, filepath.Join("pentagi", name), out, &d); err != nil {
					return err
				}
			}
		}
		if m.Path == "github.com/richardlehane/msoleps" && m.Version == "v1.0.1" {
			// This pinned module declares Apache-2.0 in its Go file headers,
			// but its published module zip contains no standalone LICENSE.
			local := filepath.Join(root, "scripts", "license-notices", "overrides", "msoleps-v1.0.1")
			var provenance struct {
				Source string `json:"source"`
				SHA256 string `json:"source_sha256"`
			}
			b, err := os.ReadFile(filepath.Join(local, "PROVENANCE.json"))
			if err != nil {
				return err
			}
			if err := json.Unmarshal(b, &provenance); err != nil {
				return err
			}
			source, err := os.ReadFile(filepath.Join(base, provenance.Source))
			if err != nil {
				return err
			}
			hash := sha256.Sum256(source)
			if hex.EncodeToString(hash[:]) != provenance.SHA256 {
				return fmt.Errorf("msoleps license source hash differs")
			}
			for _, name := range []string{"NOTICE.txt", "LICENSE-Apache-2.0.txt", "PROVENANCE.json"} {
				if err := copyNotice(local, name, filepath.Join(prefix, name), out, &d); err != nil {
					return err
				}
			}
		}
		var sources []string
		for dir := range dirs[path] {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if entry.IsDir() || !isNotice(entry.Name()) {
					continue
				}
				sources = append(sources, filepath.Join(dir, entry.Name()))
			}
		}
		sort.Strings(sources)
		for _, source := range sources {
			rel, err := filepath.Rel(base, source)
			if err != nil {
				return err
			}
			if err := copyNotice(base, rel, filepath.Join(prefix, rel), out, &d); err != nil {
				return err
			}
		}
		if len(d.Files) == 0 {
			return fmt.Errorf("no license/notice found for compiled dependency %s@%s", m.Path, m.Version)
		}
		manifest = append(manifest, d)
	}
	fontDep := dependency{Module: "hunter/bundled-fonts"}
	fontDir := filepath.Join(root, "web", "public", "licenses")
	fontFiles, err := os.ReadDir(fontDir)
	if err != nil {
		return err
	}
	for _, file := range fontFiles {
		if file.IsDir() {
			continue
		}
		if err := copyNotice(fontDir, file.Name(), filepath.Join("fonts", file.Name()), out, &fontDep); err != nil {
			return err
		}
	}
	if len(fontDep.Files) == 0 {
		return fmt.Errorf("bundled font notices missing")
	}
	manifest = append(manifest, fontDep)
	reportDir := filepath.Join(root, "internal", "app", "report_assets")
	var reportOrigin struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	origin, err := os.ReadFile(filepath.Join(reportDir, "UPSTREAM.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(origin, &reportOrigin); err != nil {
		return err
	}
	for _, name := range []string{"NanumGothic-Regular.ttf", "OFL.txt"} {
		raw, err := os.ReadFile(filepath.Join(reportDir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != reportOrigin.Files[name].SHA256 {
			return fmt.Errorf("report font origin hash differs: %s", name)
		}
	}
	reportDep := dependency{Module: "hunter/report-font/NanumGothic", Version: "Google Fonts commit 133ccbee9a8b408eb71f31a36ccb9116f5c695ad"}
	for _, name := range []string{"OFL.txt", "UPSTREAM.json"} {
		if err := copyNotice(reportDir, name, filepath.Join("fonts", "nanumgothic", name), out, &reportDep); err != nil {
			return err
		}
	}
	manifest = append(manifest, reportDep)

	goRoot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return err
	}
	goDep := dependency{Module: "Go standard library"}
	if err := copyNotice(strings.TrimSpace(string(goRoot)), "LICENSE", "go/LICENSE", out, &goDep); err != nil {
		return err
	}
	manifest = append(manifest, goDep)
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "dependencies.json"), append(encoded, '\n'), 0644); err != nil {
		return err
	}
	// Preserve the recorded explanation for the upstream SDK NOTICE mismatch.
	architecture, err := os.ReadFile(filepath.Join(root, "scripts", "license-notices", "PENTAGI-NOTICE.md"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "PENTAGI-NOTICE.md"), architecture, 0644); err != nil {
		return err
	}
	fmt.Printf("Collected license notices for %d modules and bundled components in %s\n", len(manifest), out)
	return nil
}

func isNotice(name string) bool {
	// A package can contain implementation files named license.go or notice.ts.
	// They are not redistribution notices and must not enter the runtime image.
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".c", ".h", ".cc", ".cpp", ".py", ".sh":
		return false
	}
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT", "AUTHORS"} {
		if upper == prefix || strings.HasPrefix(upper, prefix+".") || strings.HasPrefix(upper, prefix+"-") {
			return true
		}
	}
	return false
}

func copyNotice(base, source, target, out string, dep *dependency) error {
	data, err := os.ReadFile(filepath.Join(base, source))
	if err != nil {
		return fmt.Errorf("read notice %s: %w", filepath.Join(base, source), err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("empty notice: %s", source)
	}
	dest := filepath.Join(out, target)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(dest, data, 0644); err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	dep.Files = append(dep.Files, notice{Path: filepath.ToSlash(target), SHA256: hex.EncodeToString(hash[:])})
	return nil
}
