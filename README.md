# go-ntlmssp

[![Go Reference](https://pkg.go.dev/badge/github.com/edanko/go-ntlmssp.svg)](https://pkg.go.dev/github.com/edanko/go-ntlmssp) [![Test](https://github.com/Azure/go-ntlmssp/actions/workflows/test.yml/badge.svg)](https://github.com/Azure/go-ntlmssp/actions/workflows/test.yml)

Go package that provides NTLM/Negotiate authentication over HTTP.

> **This is a fork of [Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp)**,
> tracking its `master` branch. It adds the one capability upstream lacks: the
> **GSS channel binding** (`tls-server-end-point`) that IIS requires when a site
> runs with *Extended Protection: Required*, which is how a hardened ADCS web
> enrollment service is configured. Without it, authentication against such a
> site fails with `401` even when the credentials are correct, and reports the
> same error as a wrong password.
>
> The fork also sends the service principal name in `MsvAvTargetName`, which
> those sites use to select the account to authenticate.
>
> Upstream is the maintained implementation and this fork is meant to be
> short-lived: if the channel binding lands in
> [Azure/go-ntlmssp](https://github.com/Azure/go-ntlmssp), switch back to it.
> Only the module path differs, so that consumers can depend on this fork
> without a `replace` directive — which is the whole point, since a `replace` is
> honoured only by the main module and would be invisible to every program
> importing a library that needs it.

* NTLM protocol details from https://msdn.microsoft.com/en-us/library/cc236621.aspx
* NTLM over HTTP details from https://datatracker.ietf.org/doc/html/rfc4559
* Implementation hints from http://davenport.sourceforge.net/ntlm.html

This package only implements authentication, no key exchange or encryption. It
only supports Unicode (UTF16LE) encoding of protocol strings, no OEM encoding.
This package implements NTLMv2.

# Installation

To install the package, use `go get`:

```bash
go get github.com/edanko/go-ntlmssp
```

# Usage

```go
url, user, password := "http://www.example.com/secrets", "robpike", "pw123"
client := &http.Client{
  Transport: ntlmssp.Negotiator{
    RoundTripper: &http.Transport{},
  },
}

req, _ := http.NewRequest("GET", url, nil)
req.SetBasicAuth(user, password)
res, _ := client.Do(req)
```

-----
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
