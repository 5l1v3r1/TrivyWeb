package python

import (
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"golang.org/x/xerrors"

	"github.com/knqyf263/go-dep-parser/pkg/pipenv"
	"github.com/knqyf263/go-dep-parser/pkg/poetry"
	ptypes "github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"
)

const (
	ScannerTypePipenv = "pipenv"
	ScannerTypePoetry = "poetry"
)

type Scanner struct {
	db          AdvisoryDB
	scannerType string
}

func NewScanner(scannerType string) *Scanner {
	return &Scanner{scannerType: scannerType}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]vulnerability.DetectedVulnerability, error) {
	var vulns []vulnerability.DetectedVulnerability
	for _, advisory := range s.db[pkgName] {
		if !utils.MatchVersions(pkgVer, advisory.Specs) {
			continue
		}

		vulnerabilityID := advisory.Cve
		if vulnerabilityID == "" {
			vulnerabilityID = advisory.ID
		}

		vuln := vulnerability.DetectedVulnerability{
			VulnerabilityID:  vulnerabilityID,
			PkgName:          pkgName,
			Title:            strings.TrimSpace(advisory.Advisory),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     createFixedVersions(advisory.Specs),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func createFixedVersions(specs []string) string {
	var fixedVersions []string
	for _, spec := range specs {
		for _, s := range strings.Split(spec, ",") {
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				fixedVersions = append(fixedVersions, strings.TrimPrefix(s, "<"))
			}
		}
	}
	return strings.Join(fixedVersions, ", ")
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	if s.Type() == ScannerTypePipenv {
		return s.parsePipenv(f)
	}
	return s.parsePoetry(f)
}

func (s *Scanner) parsePipenv(f *os.File) ([]ptypes.Library, error) {
	libs, err := pipenv.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Pipfile.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) parsePoetry(f *os.File) ([]ptypes.Library, error) {
	libs, err := poetry.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid poetry.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) Type() string {
	return s.scannerType
}
