package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// coloISO maps an IATA colo code to its ISO 3166 alpha-2 country, resolved once
// per run (resolveColoISO) and read while rendering. Nil-safe: a miss yields no
// flag. Package-level like errPal - single run, single writer.
var coloISO map[string]string

// coloFlag returns the flag emoji for a colo's country, or "" if unknown.
func coloFlag(colo string) string { return flagEmoji(coloISO[colo]) }

const regionalIndicatorA = 0x1F1E6 // 🇦

// flagEmoji maps a 2-letter ISO country code to its regional-indicator flag.
// Returns "" for anything that isn't exactly two ASCII letters ("?", "", junk).
func flagEmoji(iso string) string {
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

// resolveColoISO looks up the country of every unique, non-empty colo. Sequential
// (a handful of colos per run); a failed lookup is simply left out of the map.
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

// iataISO returns the ISO country of an IATA airport code via the air-port-codes
// API (ported from the bash get_iata_location). "" on any failure.
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
