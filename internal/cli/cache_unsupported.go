//go:build !darwin && !linux

package cli

import (
	"context"
	"errors"
)

type credentialCache struct{}

func openCache(context.Context, string) (*credentialCache, error) {
	return nil, errors.New("protected credential storage is unsupported on this platform")
}
func (*credentialCache) close() {}
func (*credentialCache) read() (*cachedSession, error) {
	return nil, errors.New("protected credential storage is unsupported on this platform")
}
func (*credentialCache) write(cachedSession) error {
	return errors.New("protected credential storage is unsupported on this platform")
}
func (*credentialCache) remove(*cachedSession) error {
	return errors.New("protected credential storage is unsupported on this platform")
}
