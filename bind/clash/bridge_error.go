package clash

import (
	"reflect"
	"strings"
	"unicode/utf8"
)

func bridgeSafeError(err error) error {
	if err == nil {
		return nil
	}
	if value := reflect.ValueOf(err); value.Kind() == reflect.Ptr && value.IsNil() {
		return &bridgeRepairedError{
			message: "clash: internal: error value is a typed nil (" + value.Type().String() + ")",
		}
	}
	message := err.Error()
	if utf8.ValidString(message) {
		return err
	}
	return &bridgeRepairedError{message: strings.ToValidUTF8(message, "�"), inner: err}
}

type bridgeRepairedError struct {
	message string
	inner   error
}

func (e *bridgeRepairedError) Error() string { return e.message }

func (e *bridgeRepairedError) Unwrap() error { return e.inner }
