// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

type Fingerprinter struct {
	AllowBluntMimicry bool
	AlwaysAddPadding bool
}

func (f *Fingerprinter) FingerprintClientHello(data []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	return f.RawClientHello(data)
}

func (f *Fingerprinter) RawClientHello(raw []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	clientHelloSpec = &ClientHelloSpec{}
	err = clientHelloSpec.FromRaw(raw, f.AllowBluntMimicry)
	if err != nil {
		return nil, err
	}

	if f.AlwaysAddPadding {
		clientHelloSpec.AlwaysAddPadding()
	}

	return clientHelloSpec, nil
}

func (f *Fingerprinter) UnmarshalJSONClientHello(json []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	clientHelloSpec = &ClientHelloSpec{}
	err = clientHelloSpec.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}

	if f.AlwaysAddPadding {
		clientHelloSpec.AlwaysAddPadding()
	}

	return clientHelloSpec, nil
}
