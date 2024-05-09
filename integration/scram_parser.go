package integration

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type s1Msg struct {
	nonce string
	salt  []byte
	iters int
}

type s2Msg struct {
	verifier []byte
	err      string
}

func parseField(s, k string) (string, error) {
	t := strings.TrimPrefix(s, k+"=")
	if t == s {
		return "", fmt.Errorf("error parsing '%s' for field '%s'", s, k)
	}
	return t, nil
}

func parseFieldBase64(s, k string) ([]byte, error) {
	raw, err := parseField(s, k)
	if err != nil {
		return nil, err
	}

	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}

	return dec, nil
}

func parseFieldInt(s, k string) (int, error) {
	raw, err := parseField(s, k)
	if err != nil {
		return 0, err
	}

	num, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("error parsing field '%s': %w", k, err)
	}

	return num, nil
}

func parseServerFirst(s1 string) (s1Msg, error) {
	var msg s1Msg
	var err error

	// Check for unsupported extensions field "m".
	if strings.HasPrefix(s1, "m=") {
		err = errors.New("SCRAM message extensions are not supported")
		return msg, err
	}

	fields := strings.Split(s1, ",")
	if len(fields) < 3 {
		err = errors.New("not enough fields in first server message")
		return msg, err
	}

	if msg.nonce, err = parseField(fields[0], "r"); err != nil {
		return msg, err
	}

	if msg.salt, err = parseFieldBase64(fields[1], "s"); err != nil {
		return msg, err
	}

	msg.iters, err = parseFieldInt(fields[2], "i")

	return msg, err
}

func parseServerFinal(s2 string) (s2Msg, error) {
	var msg s2Msg
	var err error
	fields := strings.Split(s2, ",")

	if msg.verifier, err = parseFieldBase64(fields[0], "v"); err == nil {
		return msg, nil
	}

	msg.err, err = parseField(fields[0], "e")

	return msg, err
}
