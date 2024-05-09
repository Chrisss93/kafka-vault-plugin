package main

import "github.com/xdg-go/scram"

type SCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	scram.HashGeneratorFcn
}

func (x *SCRAMClient) Begin(userName, password, authzID string) error {
	var err error
	if x.Client, err = x.HashGeneratorFcn.NewClient(userName, password, authzID); err != nil {
		return err
	}
	x.ClientConversation = x.Client.NewConversation()
	return err
}

func (x *SCRAMClient) Step(challenge string) (string, error) {
	return x.ClientConversation.Step(challenge)
}

func (x *SCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}
