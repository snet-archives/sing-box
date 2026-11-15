package browserhdr

import (
	"hash/fnv"
	"math"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func newInstanceRand() *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(runtime.GOOS))
	_, _ = h.Write([]byte(runtime.GOARCH))
	_, _ = h.Write([]byte(strconv.Itoa(runtime.NumCPU())))
	if host, err := os.Hostname(); err == nil {
		_, _ = h.Write([]byte(host))
	}
	return rand.New(rand.NewSource(int64(h.Sum64())))
}

var instanceRng = newInstanceRand()

var safariMinorMap = [25]int{
	0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
}

// ChromeVersion returns a coherent current Chromium major version.
func ChromeVersion() int {
	const baseVersion = 144
	startDay := time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	curDay := time.Now().UTC().Unix() / 86400
	diff := int(curDay-startDay-35) - int(math.Floor(math.Pow(instanceRng.Float64(), 2)*105))
	v := baseVersion + (diff / 35)
	if v < 133 {
		return 133
	}
	return v
}

// FirefoxVersion returns a coherent current Firefox major version.
func FirefoxVersion() int {
	startDay := time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	curDay := time.Now().UTC().Unix() / 86400
	diff := curDay - startDay - 25 - int64(math.Floor(math.Pow(instanceRng.Float64(), 2)*50))
	v := int(diff/30) + 128
	if v < 128 {
		return 128
	}
	return v
}

// SafariVersion returns a coherent current Safari major.minor string.
func SafariVersion() string {
	now := time.Now().UTC()
	year := now.Year()
	splitPoint := time.Date(year, 9, 23, 0, 0, 0, 0, time.UTC)
	delayedDays := int(math.Floor(math.Pow(instanceRng.Float64(), 3) * 75))
	splitPoint = splitPoint.AddDate(0, 0, delayedDays)
	if now.Before(splitPoint) {
		year--
		splitPoint = time.Date(year, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delayedDays)
	}
	idx := int((now.Unix() - splitPoint.Unix()) / 1296000)
	if idx < 0 {
		idx = 0
	} else if idx >= len(safariMinorMap) {
		idx = len(safariMinorMap) - 1
	}
	major := year - 1999
	if major < 18 {
		major = 18
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(safariMinorMap[idx])
}

// CurlVersion returns a coherent current curl version string.
func CurlVersion() string {
	curDay := time.Now().UTC().Unix() / 86400
	startDay := time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	diff := int(curDay-startDay-60) - int(math.Floor(math.Pow(instanceRng.Float64(), 2)*165))
	minor := diff / 57
	if minor < 10 {
		minor = 10
	}
	return "8." + strconv.Itoa(minor) + ".0"
}

var (
	chGreaseChars = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	chGreaseVers  = []string{"8", "99", "24"}
	chShuffle3    = [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	chShuffle4    = [][4]int{
		{0, 1, 2, 3}, {0, 1, 3, 2}, {0, 2, 1, 3}, {0, 2, 3, 1}, {0, 3, 1, 2}, {0, 3, 2, 1},
		{1, 0, 2, 3}, {1, 0, 3, 2}, {1, 2, 0, 3}, {1, 2, 3, 0}, {1, 3, 0, 2}, {1, 3, 2, 0},
		{2, 0, 1, 3}, {2, 0, 3, 1}, {2, 1, 0, 3}, {2, 1, 3, 0}, {2, 3, 0, 1}, {2, 3, 1, 0},
		{3, 0, 1, 2}, {3, 0, 2, 1}, {3, 1, 0, 2}, {3, 1, 2, 0}, {3, 2, 0, 1}, {3, 2, 1, 0},
	}
)

func greasedBrand(seed int) string {
	c1 := chGreaseChars[seed%len(chGreaseChars)]
	c2 := chGreaseChars[(seed+1)%len(chGreaseChars)]
	v := chGreaseVers[seed%len(chGreaseVers)]
	return `"Not` + c1 + `A` + c2 + `Brand";v="` + v + `"`
}

func greasedOrder(n, seed int) []int {
	switch n {
	case 1:
		return []int{0}
	case 2:
		return []int{seed % 2, (seed + 1) % 2}
	case 3:
		return chShuffle3[seed%len(chShuffle3)][:]
	default:
		return chShuffle4[seed%len(chShuffle4)][:]
	}
}

func greasedSecCHUA(major int, fork string) string {
	brands := make([]string, 0, 3)
	brands = append(brands, greasedBrand(major), `"Chromium";v="`+strconv.Itoa(major)+`"`)
	switch fork {
	case "chrome":
		brands = append(brands, `"Google Chrome";v="`+strconv.Itoa(major)+`"`)
	case "edge":
		brands = append(brands, `"Microsoft Edge";v="`+strconv.Itoa(major)+`"`)
	}
	order := greasedOrder(len(brands), major)
	out := make([]string, len(brands))
	for i, pos := range order {
		out[pos] = brands[i]
	}
	return strings.Join(out, ", ")
}

var (
	AnchoredChromeMajor  = ChromeVersion()
	AnchoredFirefoxMajor = FirefoxVersion()
	AnchoredSafariVer    = SafariVersion()
	AnchoredCurlVer      = CurlVersion()
)

func chromeUA(major int) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(major) + ".0.0.0 Safari/537.36"
}

func edgeUA(major int) string {
	return chromeUA(major) + " Edg/" + strconv.Itoa(major) + ".0.0.0"
}

func firefoxUA(major int) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + strconv.Itoa(major) + ".0) Gecko/20100101 Firefox/" + strconv.Itoa(major) + ".0"
}

func safariUA(ver string) string {
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + ver + " Safari/605.1.15"
}

type profileSpec struct {
	family  string
	major   int
	version string
}

func parseProfile(name string) (profileSpec, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "", n == "chrome", strings.HasPrefix(n, "chrome_"), n == "random", n == "randomized", n == "randomized_no_alpn", n == "360", n == "qq", n == "android":
		spec := profileSpec{family: "chrome", major: AnchoredChromeMajor}
		switch {
		case strings.HasPrefix(n, "chrome_1"):
			if v, err := strconv.Atoi(strings.TrimPrefix(n, "chrome_")); err == nil && v >= 100 {
				spec.major = v
			}
		case n == "chrome_pq":
			spec.major = 120
		case n == "chrome_pq_psk":
			spec.major = 115
		case n == "chrome_padding_psk_shuffle":
			spec.major = 114
		case n == "chrome_psk_shuffle":
			spec.major = 112
		case n == "chrome_psk":
			spec.major = 100
		}
		return spec, true
	case n == "edge", strings.HasPrefix(n, "edge_"):
		spec := profileSpec{family: "edge", major: AnchoredChromeMajor}
		if strings.HasPrefix(n, "edge_") {
			if v, err := strconv.Atoi(strings.TrimPrefix(n, "edge_")); err == nil && v >= 85 {
				spec.major = v
			}
		}
		return spec, true
	case n == "firefox", strings.HasPrefix(n, "firefox_"):
		spec := profileSpec{family: "firefox", major: AnchoredFirefoxMajor}
		if strings.HasPrefix(n, "firefox_") {
			if v, err := strconv.Atoi(strings.TrimPrefix(n, "firefox_")); err == nil && v >= 90 {
				spec.major = v
			}
		}
		return spec, true
	case n == "safari", strings.HasPrefix(n, "safari_"), n == "ios":
		spec := profileSpec{family: "safari", version: AnchoredSafariVer}
		if strings.HasPrefix(n, "safari_") {
			ver := strings.ReplaceAll(strings.TrimPrefix(n, "safari_"), "_", ".")
			if ver != "" {
				spec.version = ver
			}
		}
		return spec, true
	case n == "curl":
		return profileSpec{family: "curl"}, true
	case n == "golang", n == "go":
		return profileSpec{family: "golang"}, true
	default:
		return profileSpec{}, false
	}
}

// ApplyForUTLS sets realistic browser headers matching a uTLS ClientHelloID's
// client family and pinned version, combined with the fetch/nav/ws variant.
func ApplyForUTLS(header http.Header, client, version, variant string) {
	if header == nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(client))
	if name == "randomized" || name == "randomizednoalpn" || name == "randomized-no-alpn" || name == "" {
		name = "chrome"
	}
	if version != "" && version != "0" && (name == "chrome" || name == "firefox" || name == "edge") {
		if _, err := strconv.Atoi(version); err == nil {
			name = name + "_" + version
		}
	} else if version != "" && version != "0" && name == "safari" {
		name = "safari_" + strings.ReplaceAll(version, ".", "_")
	}
	spec, ok := parseProfile(name)
	if !ok {
		spec = profileSpec{family: "chrome", major: AnchoredChromeMajor}
	}
	applySpec(header, spec, variant, true)
}

// TryDefaultHeadersWith populates coherent browser headers on header for the
// given variant ("nav", "fetch", "ws"), honoring special User-Agent tokens
// ("chrome", "firefox", "safari", "edge", "curl", "golang", or pinned names)
// while leaving arbitrary custom User-Agent values intact.
func TryDefaultHeadersWith(header http.Header, variant string) {
	if header == nil {
		return
	}
	vals := header.Values("User-Agent")
	if len(vals) == 0 {
		applySpec(header, profileSpec{family: "chrome", major: AnchoredChromeMajor}, variant, true)
		return
	}
	if spec, ok := parseProfile(vals[0]); ok {
		applySpec(header, spec, variant, true)
		return
	}
	// Preserve caller's custom User-Agent; only fill missing fetch metadata.
	applySpec(header, profileSpec{family: "chrome", major: AnchoredChromeMajor}, variant, false)
}

func applySpec(header http.Header, spec profileSpec, variant string, applyIdentity bool) {
	if applyIdentity {
		switch spec.family {
		case "chrome":
			header.Del("Sec-CH-UA")
			header.Del("Sec-CH-UA-Mobile")
			header.Del("Sec-CH-UA-Platform")
			header["Sec-CH-UA"] = []string{greasedSecCHUA(spec.major, "chrome")}
			header["Sec-CH-UA-Mobile"] = []string{"?0"}
			header["Sec-CH-UA-Platform"] = []string{`"Windows"`}
			header.Set("User-Agent", chromeUA(spec.major))
			if header.Get("Accept-Language") == "" {
				header.Set("Accept-Language", "en-US,en;q=0.9")
			}
		case "edge":
			header.Del("Sec-CH-UA")
			header.Del("Sec-CH-UA-Mobile")
			header.Del("Sec-CH-UA-Platform")
			header["Sec-CH-UA"] = []string{greasedSecCHUA(spec.major, "edge")}
			header["Sec-CH-UA-Mobile"] = []string{"?0"}
			header["Sec-CH-UA-Platform"] = []string{`"Windows"`}
			header.Set("User-Agent", edgeUA(spec.major))
			if header.Get("Accept-Language") == "" {
				header.Set("Accept-Language", "en-US,en;q=0.9")
			}
		case "firefox":
			header.Set("User-Agent", firefoxUA(spec.major))
			if header.Get("Accept-Language") == "" {
				header.Set("Accept-Language", "en-US,en;q=0.5")
			}
		case "safari":
			header.Set("User-Agent", safariUA(spec.version))
			if header.Get("Accept-Language") == "" {
				header.Set("Accept-Language", "en-US,en;q=0.9")
			}
		case "curl":
			header.Set("User-Agent", "curl/"+AnchoredCurlVer)
			return
		case "golang":
			header.Del("User-Agent")
			return
		}
	}

	switch variant {
	case "nav":
		if header.Get("Cache-Control") == "" && (spec.family == "chrome" || spec.family == "edge") {
			header.Set("Cache-Control", "max-age=0")
		}
		header.Set("Upgrade-Insecure-Requests", "1")
		if header.Get("Accept") == "" {
			switch spec.family {
			case "chrome", "edge":
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			default:
				header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			}
		}
		header.Set("Sec-Fetch-Site", "none")
		header.Set("Sec-Fetch-Mode", "navigate")
		if spec.family != "safari" {
			header.Set("Sec-Fetch-User", "?1")
		}
		header.Set("Sec-Fetch-Dest", "document")
		header.Set("Priority", "u=0, i")
	case "ws":
		header.Set("Sec-Fetch-Mode", "websocket")
		if spec.family == "safari" {
			header.Set("Sec-Fetch-Dest", "websocket")
		} else {
			header.Set("Sec-Fetch-Dest", "empty")
		}
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	case "fetch":
		header.Set("Sec-Fetch-Mode", "cors")
		header.Set("Sec-Fetch-Dest", "empty")
		header.Set("Sec-Fetch-Site", "same-origin")
		if header.Get("Priority") == "" {
			switch spec.family {
			case "chrome", "edge":
				header.Set("Priority", "u=1, i")
			case "firefox":
				header.Set("Priority", "u=4")
			case "safari":
				header.Set("Priority", "u=3, i")
			}
		}
		if header.Get("Cache-Control") == "" {
			header.Set("Cache-Control", "no-cache")
		}
		if header.Get("Pragma") == "" {
			header.Set("Pragma", "no-cache")
		}
		if header.Get("Accept") == "" {
			header.Set("Accept", "*/*")
		}
	}
}
