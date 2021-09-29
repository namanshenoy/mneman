package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/shamir"
	"github.com/tyler-smith/go-bip39"
)

func recreate(mnem_shares []string) (string, error) {
	mnems := []string{}
	last_bytes := []byte{}
	for _, m := range mnem_shares {
		mnems = append(mnems, strings.Split(m, ",")[0])
		lb, _ := strconv.Atoi(strings.Split(m, ",")[1])
		last_bytes = append(last_bytes, byte(lb))
		// print(lb)
	}
	entropies := [][]byte{}
	for i, m := range mnems {
		e, _ := bip39.EntropyFromMnemonic(m)
		e = append(e, last_bytes[i])
		entropies = append(entropies, e)
	}
	r, err := shamir.Combine(entropies)
	if err != nil {
		return "", err
	}
	mFinal, err := bip39.NewMnemonic(r)
	if err != nil {
		return "", err
	}
	return mFinal, nil
}

func createFromMnemonic(mnemonic string, total int, minShares int) ([]string, []byte, error) {
	fmt.Println("Initial: ", mnemonic)
	fmt.Println()

	hex_bytes, _ := bip39.EntropyFromMnemonic(mnemonic)
	key_slices, _ := shamir.Split(hex_bytes, total, minShares)

	last_bytes := []byte{}
	created_mnems := []string{}
	for _, share := range key_slices {
		last_byte := share[len(share)-1]
		shortened_share := share[:len(share)-1]

		mnemonic2, err := bip39.NewMnemonic(shortened_share)
		if err != nil {
			return []string{}, []byte{}, err
		}
		created_mnems = append(created_mnems, mnemonic2)
		last_bytes = append(last_bytes, last_byte)
	}
	return created_mnems, last_bytes, nil
}

func writeFile(shares []string, outputFileName string) {
	if outputFileName == "" {
		fmt.Println("Writing to shares.txt You can replace the filename by using the -output flag")
		outputFileName = "shares.txt"
	}
	file, err := os.OpenFile(outputFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed creating shares file: %s", err)
	}
	datawriter := bufio.NewWriter(file)

	for i, data := range shares {
		if i == len(shares)-1 {
			print("HERE")
			_, _ = datawriter.WriteString(data)
		} else {
			print(i)
			_, _ = datawriter.WriteString(data + "\n")
		}
	}
	datawriter.Flush()
	file.Close()
}

func readFile(fileName string) []string {
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalf("failed reading shares file: %s", err)
	}
	sliceData := strings.Split(string(fileBytes), "\n")
	return sliceData
}

func main() {
	var createShares bool
	var minShareCount int
	var totalShareCount int
	var initialMnem string
	var inputFileName string
	var outputFileName string

	flag.BoolVar(&createShares, "create-shares", false, "Set this flag to create shares")
	flag.IntVar(&minShareCount, "m", 0, "Minimum shares to recreate secret")
	flag.IntVar(&totalShareCount, "n", 0, "Total shares generated")

	flag.StringVar(&initialMnem, "initial", "", "Initial mnemonic to split into shares ex: -initial \"cheese jungle blah ... silly arena brief\"")
	flag.StringVar(&inputFileName, "input", "", "Filename to read the 'mnemonic,shareId' strings to recreate the initial mnemonic")
	flag.StringVar(&outputFileName, "output", "", "Filename to dump the 'mnemonic,shareId' strings to recreate the initial mnemonic with")

	flag.Parse()

	if createShares && inputFileName != "" {
		log.Fatal("Cannot submit an input file name when creating shares. Use the -initial=\"<MNEMONIC HERE>\" flag to create the shares")
	}
	if createShares {
		if minShareCount == 0 || totalShareCount == 0 {
			fmt.Println(minShareCount)
			fmt.Println(totalShareCount)
			log.Fatal("A minimum share count and total share count must be sumbitted with the -m <MIN_SHARES> and -n <TOTAL_SHARES> flags")
		}
		if minShareCount == totalShareCount || minShareCount > totalShareCount {
			log.Fatal("The total share count must be less than the minimum share count")
		}
		if initialMnem == "" {
			log.Fatal("Use the -create-shares flag along with the --initial=\"<MNEMONIC HERE>\" flag to create shares")
		}
	}
	if !createShares && inputFileName == "" {
		log.Fatal("Use the -create-shares flag or the -input flag to create shares or recreate secret from shares")
	}

	// mnemonic := "knee urge romance leg sleep tool climb tip mention soccer wealth sell giraffe index valley turkey hazard long vessel sail crater donate lamp achieve"
	if createShares {
		created_mnems, last_bytes, err := createFromMnemonic(initialMnem, totalShareCount, minShareCount)
		if err != nil {
			log.Fatalln("Error occurred when creating mnemonic shares", err)
		}
		fmt.Println("Share mnemonics:")
		mnemonic_shares := []string{}
		for i, mnem := range created_mnems {
			share := fmt.Sprintf("%s,%d", mnem, int(last_bytes[i]))
			fmt.Println(share)
			mnemonic_shares = append(mnemonic_shares, share)
		}
		writeFile(mnemonic_shares, outputFileName)
	} else {
		if inputFileName == "" {
			fmt.Println("Reading Shares from shares.txt. To change this, use the -input <FILENAME> flag")
			inputFileName = "shares.txt"
		}
		mnemonic_shares := readFile(inputFileName)
		recreatedMnemonic, _ := recreate(mnemonic_shares)
		fmt.Println()
		fmt.Println("Recreated:", recreatedMnemonic)
	}
}
