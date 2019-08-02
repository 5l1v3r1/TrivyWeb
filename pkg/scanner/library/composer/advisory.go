package composer

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/etcd-io/bbolt"
	"github.com/knqyf263/trivy/pkg/db"
	"golang.org/x/xerrors"

	"github.com/knqyf263/trivy/pkg/utils"
	"github.com/knqyf263/trivy/pkg/vulnsrc/vulnerability"

	"github.com/knqyf263/trivy/pkg/git"
	"gopkg.in/yaml.v2"
)

const (
	dbURL = "https://github.com/FriendsOfPHP/security-advisories"
)

var (
	repoPath = filepath.Join(utils.CacheDir(), "php-security-advisories")
)

type AdvisoryDB map[string][]Advisory

type Advisory struct {
	Cve       string
	Title     string
	Link      string
	Reference string
	Branches  map[string]Branch
}

type Branch struct {
	Versions []string
}

func (s *Scanner) UpdateDB() (err error) {
	if _, err := git.CloneOrPull(dbURL, repoPath); err != nil {
		return err
	}
	s.db, err = s.walk()
	return err
}

func (s *Scanner) walk() (AdvisoryDB, error) {
	advisoryDB := AdvisoryDB{}
	var vulns []vulnerability.Vulnerability
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() || !strings.HasPrefix(info.Name(), "CVE-") {
			return nil
		}
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		advisory := Advisory{}
		err = yaml.Unmarshal(buf, &advisory)
		if err != nil {
			return err
		}

		// for detecting vulnerabilities
		advisories, ok := advisoryDB[advisory.Reference]
		if !ok {
			advisories = []Advisory{}
		}
		advisoryDB[advisory.Reference] = append(advisories, advisory)

		vulnerabilityID := advisory.Cve
		if vulnerabilityID == "" {
			// e.g. CVE-2019-12139.yaml => CVE-2019-12139
			vulnerabilityID = strings.TrimSuffix(info.Name(), ".yaml")
		}

		// for displaying vulnerability detail
		vulns = append(vulns, vulnerability.Vulnerability{
			ID:         vulnerabilityID,
			References: []string{advisory.Link},
			Title:      advisory.Title,
		})

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in file walk: %w", err)
	}
	if err = s.saveVulnerabilities(vulns); err != nil {
		return nil, err
	}
	return advisoryDB, nil
}

func (s Scanner) saveVulnerabilities(vulns []vulnerability.Vulnerability) error {
	return vulnerability.BatchUpdate(func(b *bbolt.Bucket) error {
		for _, vuln := range vulns {
			if err := db.Put(b, vuln.ID, vulnerability.PhpSecurityAdvisories, vuln); err != nil {
				return xerrors.Errorf("failed to save %s vulnerability: %w", s.Type(), err)
			}
		}
		return nil
	})
}
