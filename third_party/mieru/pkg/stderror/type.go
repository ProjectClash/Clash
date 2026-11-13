// Copyright (C) 2022  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package stderror

type ErrorType uint8

const (
	NO_ERROR ErrorType = iota
	UNKNOWN_ERROR
	PROTOCOL_ERROR
	NETWORK_ERROR
	CRYPTO_ERROR
	REPLAY_ERROR
)

type TypedError struct {
	err     error
	errType ErrorType
}

var _ error = TypedError{}

func (e TypedError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return ""
}

func (e TypedError) Unwrap() error {
	return e.err
}

func WrapErrorWithType(err error, t ErrorType) TypedError {
	return TypedError{
		err:     err,
		errType: t,
	}
}

func GetErrorType(err error) ErrorType {
	if err == nil {
		return NO_ERROR
	}
	if typedError, ok := err.(TypedError); ok {
		return typedError.errType
	}
	return UNKNOWN_ERROR
}
