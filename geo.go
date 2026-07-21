package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var coloISO map[string]string

var noEmoji bool

func coloFlag(colo string) string { return flagEmoji(coloISO[colo]) }

const regionalIndicatorA = 0x1F1E6

func flagEmoji(iso string) string {
	if noEmoji {
		return ""
	}
	if len(iso) != 2 {
		return ""
	}
	var flag strings.Builder
	for _, c := range strings.ToUpper(iso) {
		if c < 'A' || c > 'Z' {
			return ""
		}
		flag.WriteRune(regionalIndicatorA + (c - 'A'))
	}
	return flag.String()
}

const (
	airPortCodesURL = "https://www.air-port-codes.com/api/v1/single"
	airPortCodesAPC = "96dc04b3fb"
	airPortCodesRef = "https://www.air-port-codes.com/"
)

func resolveColoISO(ctx context.Context, colos []string) map[string]string {
	client := &http.Client{Timeout: registerTimeout}
	out := make(map[string]string)
	for _, colo := range colos {
		if colo == "" || colo == "?" {
			continue
		}
		if _, done := out[colo]; done {
			continue
		}
		if iso := iataISO(ctx, client, colo); iso != "" {
			out[colo] = iso
		}
	}
	return out
}

func iataISO(ctx context.Context, client *http.Client, iata string) string {
	body := strings.NewReader(url.Values{"iata": {iata}}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, airPortCodesURL, body)
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("APC-Auth", airPortCodesAPC)
	req.Header.Set("Referer", airPortCodesRef)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return ""
	}
	var r struct {
		Airport struct {
			Country struct {
				ISO string `json:"iso"`
			} `json:"country"`
		} `json:"airport"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return ""
	}
	return r.Airport.Country.ISO
}
