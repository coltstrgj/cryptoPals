package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/coltstrgj/cryptopals/hammingDistance"
	"io/ioutil"
	"os"
	"strings"
)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                  Utility Functions                                                 //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

//hexToBase64 will take in hexadecimal (A string because of the challenges, but could easily be converted to take actual hex by changing string to []byte and removing first line)
func hexToBase64(hexStr string) string {
	hex, err := hex.DecodeString(hexStr)
	check(err)
	return base64.StdEncoding.EncodeToString(hex)
}

func base64ToHex(data []byte) []byte {
	var hexStuff []byte = make([]byte, len(data))
	l, _ := base64.StdEncoding.Decode(hexStuff, data)
	return hexStuff[:l]
}

func readFile(fileName string) []byte {
	data, err := ioutil.ReadFile(fileName)
	check(err)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		fmt.Println("ERROR: File Does not exist or is blank")
		// path/to/whatever does not exist
	}
	return data
}

//countBytes will count the number of times that a byte occured. It will return a map of counts stored with their values as key.
func countBytes(data []byte) map[byte]int {
	var frequencies map[byte]int = make(map[byte]int)
	for _, character := range data {
		//increase the count of this character
		frequencies[character]++
	}
	return frequencies
}

//splitBlocks(data []byte, size int) will split data into blocks of "blockSize" in length.
func splitBlocks(data []byte, blockSize int) [][]byte {
	//TODO what if it is not an int multiple of blocksize?
	//Do I pad the last one as needed, or return staggered blocks?
	if len(data)%blockSize != 0 {
		data = append(data, make([]byte, (blockSize-(len(data)%blockSize)))...)
	}
	var numBlocks int = len(data) / blockSize
	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		end := (i + 1) * blockSize
		blocks[i] = data[start:end]
	}
	return blocks
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                  Misc Functions                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//scorePlainText will score the liklihood that a given text is the propper english plaintext from a ciphertext
//It does not work well for all messages, namely messages that include lots of punctuation or numbers (like coordinates, etc)
func chiSquareEnglish(plainText []byte) float32 {
	distribution := map[byte]float32{
		'e': 0.094498,
		'r': 0.046229,
		'g': 0.014805,
		'i': 0.054841,
		'o': 0.057409,
		'x': 0.001435,
		'j': 0.001209,
		't': 0.069873,
		'a': 0.060733,
		's': 0.049402,
		'c': 0.023115,
		'y': 0.013068,
		'q': 0.000831,
		'n': 0.053557,
		'h': 0.041470,
		'd': 0.030140,
		'u': 0.020471,
		'p': 0.015108,
		'b': 0.011633,
		'm': 0.019111,
		'w': 0.014503,
		' ': 0.120861,
		'l': 0.031273,
		'f': 0.017374,
		'v': 0.007478,
		'k': 0.005061,
		'z': 0.000680,
	}
	//iterate over all of the bytes in this plaintext and calculate chi-square distance
	var chiDist float32 = 0
	for key, val := range countBytes(plainText) {
		//distribution is a percentage, so multiply it by length of text to get expected number of that character
		var expected float32 = distribution[key] * float32(len(plainText))
		//fmt.Printf("%c %f %d\n", key, expected, val)
		diff := float32(val) - expected
		//fmt.Printf("\t %f\n", diff*diff/expected)

		//Correct for if character is not in data
		if distribution[key] == 0.0 {
			//check if these are upper case and that is the issue
			if distribution[key+0x20] == 0 {
				//TODO take care of non letter characters that actually exist (punctuation and spaces, etc)
				expected = 0.0005 * float32(len(plainText))
				diff = float32(val) - expected
				//that was not the issue, so add to chi
				//If it is greater than 0x7F, what do I do?
				//continue
			} else {
				//add hex 20 to make them lower case
				key += 0x20
				//key was updated, so update this too. Also need to weight it so caps are less likely
				expected = (distribution[key]) * float32(len(plainText))
				//Make sure that they capitals are weighted more heavily (prevents case inversion)
				//Take a look at what happens if you get rid of the +1 and run it a few times.
				diff = (float32(val) - expected) + 1
			}
		}
		chiDist += (diff * diff) / expected
	}
	return chiDist
}

func checkAvgHamming(data [][]byte, accuracy int) int {
	var hammingDist int = 0
	var spread int = len(data) / accuracy
	//TODO random indices
	//fmt.Println(len(data))
	//fmt.Println(spread)
	//fmt.Println("")
	for i := 1; i <= accuracy; i++ {
		index1 := ((i) * spread) % len(data)
		index2 := ((i + 1) * spread) % len(data)
		//fmt.Println(index)
		//fmt.Println(index + spread)
		//fmt.Println("")
		hammingDist += hammingDistance.CalculateDistance(data[index1], data[index2])
	}

	return hammingDist / accuracy
}

//findBlockSize will try to guess the block/key size of a ciphertext based on the hamming distance of blocks
//returns blockSize, blocks
func findBlockSize(cipherText []byte, minKeyLength int, maxKeyLength int) (int, [][]byte) {
	blocks := splitBlocks(cipherText, minKeyLength)
	var bestBlocks [][]byte = blocks
	var bestKeySize int = minKeyLength
	var minHammingDist float32 = float32(checkAvgHamming(blocks, 10)) / float32(minKeyLength)
	minKeyLength++
	for ; minKeyLength <= maxKeyLength; minKeyLength++ {
		//TODO TODO figure out how I will do this (how many blocks to check)
		blocks = splitBlocks(cipherText, minKeyLength)
		hammingDist := float32(checkAvgHamming(blocks, 10)) / float32(minKeyLength)
		//fmt.Printf("KeySize %d distance %f\n", minKeyLength, hammingDist)
		if hammingDist <= minHammingDist {
			minHammingDist = hammingDist
			bestKeySize = minKeyLength
			bestBlocks = blocks
		}
	}
	//fmt.Printf("Best Key size %d distance %f\n", bestKeySize, minHammingDist)
	return bestKeySize, bestBlocks
}

//bruteForceKey will take in cipher text and try to find the corresponding key. Returns the plaintext and key
func bruteForceKey(cipherText []byte, minKeyLength int, maxKeyLength int) ([]byte, []byte) {

	_, bestBlocks := findBlockSize(cipherText, minKeyLength, maxKeyLength)

	//This will effectively be the transpose of the matrix so that each of the bytes that use the same key byte will be together
	//This will allow us to use existing code to brute force them.
	singleByteGroups := make([][]byte, len(bestBlocks[0]))
	//transpose the matrix... First byte of each will use same key, so we will brute force them together.
	for i := 0; i < len(bestBlocks[0]); i++ {
		group := make([]byte, len(bestBlocks))
		singleByteGroups[i] = group
		for j, block := range bestBlocks {
			group[j] = block[i]
		}
	}

	key := make([]byte, len(singleByteGroups))
	for i, group := range singleByteGroups {
		group, groupKey, _ := bruteForceSingleByte(group)
		singleByteGroups[i] = group
		key = append(key, groupKey)
		fmt.Println(singleByteGroups[i])
	}
	fmt.Println(hex.Dump(singleByteGroups[0]))
	//transpose the matrix back. First byte of each will use same key, so we will brute force them together.
	fmt.Println("")
	fmt.Println(hex.Dump(bestBlocks[0]))
	for i, group := range singleByteGroups {
		for j, block := range bestBlocks {
			block[i] = group[j]
			bestBlocks[j] = block
		}
	}

	plainText := make([]byte, len(cipherText))
	for _, block := range bestBlocks {
		plainText = append(plainText, block...)
	}
	//fmt.Println(hex.Dump(plainText))
	//fmt.Println(hex.Dump(key))
	return plainText, key
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                  Crypto Functions                                                 //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//blockCipher will take a []byte and xor each byte against the key []byte. If the []key is not the same length, but data is a multiple of key, the will be repeated and xored.  This is intended to be used before scoring.
func blockCipher(data []byte, key []byte) ([]byte, error) {
	if len(data)%len(key) != 0 {
		//TODO don't do this. Should I pad the data? Will I use this for only ciphertext, because then no pad, but if used for plaintext also then padding is a good idea.
		//append null characters to the end for pad.
		//make will create a []byte of length needed with initial values of 0x00
		data = append(data, make([]byte, (len(key)-(len(data)%len(key))))...)
	}

	//xor every byte with the corresponding key byte
	encoded := make([]byte, len(data))
	for i, _ := range data {
		//data is xored with the corresponding key byte
		encoded[i] = data[i] ^ key[i%len(key)]
	}
	return encoded, nil
}

//fixedXor will XOR a []byte against a same length []byte
func fixedXor(data []byte, key []byte) (string, error) {

	if len(data) == len(key) {
		encoded := make([]byte, len(data))
		for i, _ := range data {
			//xor the key and data and store in encoded
			//fmt.Printf("%X  %X\n", data[i], key[i])
			encoded[i] = data[i] ^ key[i]
		}
		return hex.Dump(encoded), nil
	} else {
		return "", errors.New("Data and Key are not same length")
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                       Challenge Solution Functions                                 //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Challenge 3
//bruteForceSingleByte will try all single bytes as keys agains the ciphertext and return the most likely plaintext (likelihood is calculated using chi-square)
func bruteForceSingleByte(cipherText []byte) ([]byte, byte, float32) {
	var key byte = 0x01
	bestKey := key
	bestPlaintext, err := blockCipher(cipherText, []byte{key})
	check(err)
	var minChiSquare float32 = chiSquareEnglish(bestPlaintext)
	for ; key <= 0x80; key += 0x01 {
		plainText, err := blockCipher(cipherText, []byte{key})
		check(err)
		chiSquare := chiSquareEnglish(plainText)
		if chiSquare < minChiSquare {
			minChiSquare = chiSquare
			bestPlaintext = plainText
			bestKey = key
		}
	}
	//fmt.Printf("%b\n", bestKey)
	//fmt.Println(bestPlaintext)
	return bestPlaintext, bestKey, minChiSquare
}

//challenge 4
func challenge4(fileName string) string {
	fileContents := string(readFile(fileName))

	var dataStrings []string = strings.Split(fileContents, "\n")
	//make a slice of slices that will store bytes. (one []byte per line in file)
	var data [][]byte = make([][]byte, len(dataStrings))

	for i, val := range dataStrings {
		hexData, err := hex.DecodeString(val)
		check(err)
		data[i] = hexData
	}
	bestPlaintext, _, minChiSquare := bruteForceSingleByte([]byte(data[0]))
	for _, val := range data[1:] {
		plainText, _, chiSquare := bruteForceSingleByte([]byte(val))
		if chiSquare < minChiSquare {
			minChiSquare = chiSquare
			bestPlaintext = plainText
			//fmt.Printf("%F %d-- %s\n", chiSquare, i, plainText)
		}
	}
	return string(bestPlaintext)
}

//Challenge 5
func challenge5() string {
	data := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	//data1 := []byte("Burning 'em, if you ain't quick and nimble")
	//data2 := []byte("I go crazy when I hear a cymbal")

	//Key
	key := []byte("ICE")
	cipherText, _ := blockCipher(data, key)
	fmt.Println(hex.Dump(cipherText))
	hexAns, err := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	check(err)
	fmt.Println(hex.Dump(hexAns))
	return ""
}

//Challenge 6
func challenge6() {
	fmt.Println(hammingDistance.CalculateDistance([]byte("this is a test"), []byte("wokka wokka!!!")))
	data := base64ToHex(readFile("6.txt"))
	plainText, key := bruteForceKey(data, 2, 40)
	//as you can see, we have an issue when we pad because 0 XOR key = key.
	//TODO delete padding before deciphering
	fmt.Println(string(plainText))
	fmt.Println("Key was: " + string(key))
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                       Main                                                         //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	//fmt.Println(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	//data, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	//key, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	//encoded, _ := fixedXor(data, key)
	//fmt.Println(encoded)

	//Challenge 3
	//data, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	//fmt.Println(bruteForceSingleByte(data))

	//data, _ = hex.DecodeString("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")
	//fmt.Println(bruteForceSingleByte(data))

	//fmt.Println(challenge4("4.txt"))
	//data := base64ToHex(readFile("6.txt"))
	//fmt.Println(hex.Dump(data))
	//blocks := splitBlocks(data, 40)
	//fmt.Println(hex.Dump(blocks[4]))
	//fmt.Println(hex.Dump(blocks[8]))
	//fmt.Println(float32(hammingDistance.CalculateDistance(blocks[4], blocks[8])) / 40)

	challenge6()
}
