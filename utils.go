package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/hashicorp/vault/sdk/framework"
)

const nameKey = "name"

func randomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("Error generating random salt: ", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func getName(data *framework.FieldData) (name string, err error) {
	if v, ok := data.GetOk(nameKey); !ok {
		err = fmt.Errorf("missing: '%s'", nameKey)
	} else if name, ok = v.(string); !ok || len(name) < 1 {
		err = fmt.Errorf("'%s' cannot be empty", nameKey)
	}
	return
}
