// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/lowRISC/opentitan-provisioning/src/version/buildver"
)

func PrintVersion(exit bool) string {
	ver := buildver.FormattedStr()
	if exit {
		fmt.Println(ver)
		os.Exit(0)
	}
	log.Print(ver)
	return ver
}

// Abs calculates the absolute value of an integer.
func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func GetCurrentTimestamp() string {
	// Get the current time
	currentTime := time.Now()

	// Format the time
	timestamp := currentTime.Format("20060102_150405")

	// Append milliseconds
	milliseconds := currentTime.UnixNano() / int64(time.Millisecond) % 1000
	timestamp = fmt.Sprintf("%s_%03d", timestamp, milliseconds)

	return timestamp
}

// GenerateRandom returns random data from the rand package.
func GenerateRandom(length int) ([]byte, error) {
	data := make([]byte, length)
	_, err := rand.Read(data)
	if err != nil {
		return nil, fmt.Errorf("fail to generate data, error: %v", err)
	}
	return data, nil
}

// ReadFile reads data from file.
// If succeed, ReadFile returns the data of the file as byte array;
// otherwise ReadFile returns an error.
func ReadFile(filename string) ([]byte, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %q, error: %v",
			filename, err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ReadFileFromDir(configDir, filename string) ([]byte, error) {
	absPath := filepath.Join(configDir, filename)
	data, err := ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read file: %q, error: %v", absPath, err)
	}
	return data, nil
}

// WriteFile writes data to the named file, creating it if necessary.
// If the file does not exist, WriteFile creates it with permissions perm (before umask);
// otherwise WriteFile appends it before writing, without changing permissions.
func WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func WriteFileToDir(configDir, filename string, data []byte) error {
	absPath := filepath.Join(configDir, filename)
	log.Printf("Debug: write data record to path %q", absPath)
	err := WriteFile(absPath, data, 0777)
	if err != nil {
		return fmt.Errorf("failed to write data to path %q: %v", absPath, err)
	}
	return nil
}

func setDefaults(config interface{}) {
	t := reflect.TypeOf(config).Elem()
	v := reflect.ValueOf(config).Elem()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		defaultTag := field.Tag.Get("default")
		if defaultTag != "" && value.Interface() == reflect.Zero(value.Type()).Interface() {
			defaultValue := reflect.ValueOf(defaultTag)
			value.Set(defaultValue)
		}
	}
}

// LoadConfig reads a Yaml configuration file from the specified path with
// filename and unmarshals it into the provided struct (v).
//
// Parameters:
//   - configDir:  The directory path of the Yaml configuration file.
//   - configFile: The file path of the Yaml configuration file.
//   - v:          A pointer to the struct where the configuration will be unmarshaled.
//
// Returns:
//   - An error if there was an issue reading or unmarshaling the configuration file.
func LoadConfig(configDir, configFile string, v interface{}) error {
	yamlData, err := ReadFileFromDir(configDir, configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration file: %v", err)
	}

	err = yaml.Unmarshal(yamlData, v)
	if err != nil {
		// Return an error if the YAML does not match any known configuration types
		return fmt.Errorf("failed to unmarshal configuration file: %v", err)
	}

	setDefaults(v)

	return nil
}

// LoadJSONConfig reads a JSON configuration file from the specified path and
// unmarshals it into the provided struct (v).
//
// Parameters:
//   - configPath: The file path of the JSON configuration file.
//   - v:          A pointer to the struct where the configuration will be unmarshaled.
//
// Returns:
//   - An error if there was an issue reading or unmarshaling the configuration file.
func LoadJSONConfig(configPath string, v interface{}) error {
	// Read the contents of the JSON file.
	data, err := ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration file: %v", err)
	}

	// Unmarshal the JSON data into the provided struct.
	err = json.Unmarshal(data, v)
	if err != nil {
		// Return an error if the JSON does not match the provided struct.
		return fmt.Errorf("failed to unmarshal configuration file: %v", err)
	}

	return nil
}

// LoadCertFromFile reads a yaml configuration file from the specified path and
// parse it into the certificate object.
//
// Parameters:
//   - configDir: The directory path of the Yaml configuration file.
//   - filename:  The filename.
//
// Returns:
//   - A pointer to the X509 certificate struct where the configuration will be parsed.
//   - An error if there was an issue reading or unmarshaling the configuration file.
func LoadCertFromFile(configDir, filename string) (*x509.Certificate, error) {
	cert, err := ReadFileFromDir(configDir, filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate file, error: %v", err)
	}

	certObj, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate, error: %v", err)
	}
	return certObj, nil
}

func CalcXorByteArrays(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("byte arrays must have the same length")
	}
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func GenerateHashFromPassword(data []byte) ([]byte, error) {
	hashData, err := bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate hash fail: %q", err)
	}
	return hashData, nil
}

func CompareHashAndPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Printf("compare hash fail: %q", err)
		return status.Errorf(codes.Internal, "compare hash fail: %q", err)
	}
	return nil
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// CalcHashPW returns a hash string value.
func CalcHashPW(password_A, password_B []byte) (string, string, error) {
	// XOR the byte arrays
	xorResult, err := CalcXorByteArrays(password_A, password_B)
	if err != nil {
		fmt.Printf("could not complete the xor operation: %s\n", err)
		return "", "", fmt.Errorf("could not complete the xor operation: %s\n", err)
	}

	Base64_password := Base64Encode(xorResult)
	hashedPassword, err := GenerateHashFromPassword([]byte(Base64_password))
	return Base64_password, string(hashedPassword), nil
}

func DERCertToPEMString(blob []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: blob,
	}
	return string(pem.EncodeToMemory(block))
}

func BytesToStr(byteArray []byte, delimiter string) string {
	var str string
	for i, v := range byteArray {
		str += strconv.Itoa(int(v))
		if i < len(byteArray)-1 {
			str += delimiter
		}
	}
	return str
}

func NumToStr(byteArray []byte, isBigEndian bool) string {
	var str string
	for _, val := range byteArray {
		if isBigEndian {
			str += fmt.Sprintf("%X%X", val>>4, val&0x0F)
		} else {
			str += fmt.Sprintf("%X%X", val&0x0F, val>>4)
		}
	}
	return str
}

// Reverses the byte slice in place.
// TODO(#155): Migrate to `slices.Reverse` in Go >= 1.21.
func Reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
