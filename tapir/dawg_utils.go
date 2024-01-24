/*
 * Copyright (c) DNS TAPIR
 */
package tapir

import (
        "bufio"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"
	"os"
	"sync"
	"time"

	"archive/zip"
	"encoding/csv"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"

	"github.com/miekg/dns"

	"github.com/smhanov/dawg"
	"github.com/spaolacci/murmur3"
)

type wellKnownDomainsTracker struct {
	mutex sync.RWMutex
	wellKnownDomainsData
}

type wellKnownDomainsData struct {
	// Store a pointer to histogramCounters so we can assign to it without
	// "cannot assign to struct field in map" issues
	rotationTime  time.Time
	dawgFinder    dawg.Finder
	murmur3Hasher hash.Hash64
}

func newWellKnownDomainsTracker(dawgFinder dawg.Finder) (*wellKnownDomainsTracker, error) {

	// Create random uint32, rand.Int takes a half-open range so we give it [0,4294967296)
	randInt, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return nil, fmt.Errorf("newWellKnownDomainsTracker: %w", err)
	}
	murmur3Seed := uint32(randInt.Uint64())

	murmur3Hasher := murmur3.New64WithSeed(murmur3Seed)

	return &wellKnownDomainsTracker{
		wellKnownDomainsData: wellKnownDomainsData{
			dawgFinder:    dawgFinder,
			murmur3Hasher: murmur3Hasher,
		},
	}, nil
}

func (wkd *wellKnownDomainsTracker) isWellKnown(name string) (bool, int) {

//	wkd.mutex.Lock()
//	defer wkd.mutex.Unlock()

	index := wkd.dawgFinder.IndexOf(name)

	// If this is is not a well-known domain just return as fast as possible
	if index == -1 {
		return false, 0
	}

	return true, index
}

func (wkd *wellKnownDomainsTracker) rotateTracker(dawgFile string, rotationTime time.Time) (*wellKnownDomainsData, error) {

	dawgFinder, err := dawg.Load(dawgFile)
	if err != nil {
		return nil, fmt.Errorf("rotateTracker: dawg.Load(): %w", err)
	}

	prevWKD := &wellKnownDomainsData{}

	// Swap the map in use so we can write parquet data outside of the write lock
	wkd.mutex.Lock()
	prevWKD.dawgFinder = wkd.dawgFinder
	wkd.dawgFinder = dawgFinder
	wkd.mutex.Unlock()

	prevWKD.rotationTime = rotationTime

	return prevWKD, nil
}

const (
	domainsFileName = "top10milliondomains.csv.zip"
	dawgFileName    = "well-known-domains.dawg"
)

func fetchFile(domainsFileName string) error {

	if domainsFileName == "" {
		return errors.New("fetchFile: domainsFileName cannot be empty")
	}

	file, err := os.Create(domainsFileName) // #nosec G304 -- The variable is a constant
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	url, err := url.Parse(fmt.Sprintf("%s/%s", "https://www.domcop.com/files/top", domainsFileName))
	if err != nil {
		return err
	}

	fmt.Printf("fetching %s\n", url)
	resp, err := http.Get(url.String())
	if err != nil {
		return err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func createDomainsList(domainsFileName string) ([]string, error) {

	if domainsFileName == "" {
		return nil, errors.New("extractFile: domainsFileName cannot be empty")
	}

	fmt.Println("creating domain list")
	file, err := os.Open(domainsFileName) // #nosec G304 -- The variable is a constant
	if err != nil {
		return nil, err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	r, err := zip.OpenReader(domainsFileName)
	if err != nil {
		return nil, err
	}

	if len(r.File) != 1 {
		return nil, errors.New("only one file is expected in the zip file")
	}

	sortedDomains := []string{}

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() {
			err = rc.Close()
			if err != nil {
				log.Fatal(err)
			}
		}()
		csvReader := csv.NewReader(rc)

		// Skip the first line containing the header
		_, err = csvReader.Read()
		if err != nil {
			return nil, err
		}

		for {
			record, err := csvReader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}

			// Make sure the domain is fully qualified (includes
			// the root domain dot at the end) as this is expected
			// by miekg/dns when comparing against a dns question
			// section name
			sortedDomains = append(sortedDomains, dns.Fqdn(record[1]))
		}
		// The names need to be sorted when adding them to the dawg
		// datastructure otherwise the operation can fail:
		// panic: d.AddWord(): Words not in alphabetical order
		slices.Sort(sortedDomains)
	}

	return sortedDomains, nil
}

func ParseCSV(srcfile string) ([]string, error) {
	fmt.Println("Creating sorted domain list from CSV")
	ifd, err := os.Open(srcfile)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := ifd.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sortedDomains := []string{}
	csvReader := csv.NewReader(ifd)

	// Skip the first line containing the header
	_, err = csvReader.Read()
	if err != nil {
		return nil, err
	}

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Make sure the domain is fully qualified (includes
		// the root domain dot at the end) as this is expected
		// by miekg/dns when comparing against a dns question
		// section name
		sortedDomains = append(sortedDomains, dns.Fqdn(record[1]))
	}
	// The names need to be sorted when adding them to the dawg
	// datastructure otherwise the operation can fail:
	// panic: d.AddWord(): Words not in alphabetical order
	slices.Sort(sortedDomains)
	return sortedDomains, nil
}

func ParseText(srcfile string) ([]string, error) {

	fmt.Println("Creating sorted domain list from text")
	ifd, err := os.Open(srcfile)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := ifd.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sortedDomains := []string{}

	scanner := bufio.NewScanner(ifd)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		sortedDomains = append(sortedDomains, dns.Fqdn(scanner.Text()))
	}
	slices.Sort(sortedDomains)
	return sortedDomains, nil
}

// Create a DAWG datastructure
func makeDAWGWords(sortedDomains []string, dawgFileName string) error {
	fmt.Printf("creating dawg file %s\n", dawgFileName)
	dawg := dawg.New()
	for _, domain := range sortedDomains {
		dawg.Add(domain)
	}

	finder := dawg.Finish()

	_, err := finder.Save(dawgFileName)
	if err != nil {
		return err
	}

	return nil
}

func CreateDawg(sortedDomains []string, outfile string) error {
	fmt.Printf("Creating DAWG data structure\n")
	dawg := dawg.New()
	for _, domain := range sortedDomains {
		dawg.Add(domain)
		if GlobalCF.Debug {
			fmt.Printf("Added \"%s\" to DAWG\n", domain)
		}
	}

	finder := dawg.Finish()

	fmt.Printf("Saving DAWG to file %s\n", outfile)
	_, err := finder.Save(outfile)
	if err != nil {
		return err
	}

	return nil
}

// func main() {
// 	_, err := os.Stat(domainsFileName)
// 	if errors.Is(err, os.ErrNotExist) {
// 		err := fetchFile(domainsFileName)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 	} else if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	domainsList, err := createDomainsList(domainsFileName)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	err = makeDAWGWords(domainsList, dawgFileName)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }
