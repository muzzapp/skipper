package device_integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/language"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/zalando/skipper/filters"
)

type errorResponse struct {
	Error errorObj `json:"error"`
}

type errorObj struct {
	Status  int             `json:"status"`
	Details errorObjDetails `json:"details"`
}

type errorObjDetails struct {
	Message string `json:"message"`
}

// isProtectedRoute Check if the HTTP route
func isProtectedRoute(r *http.Request, requestBody []byte) bool {
	uri := r.URL.RequestURI()

	if uri == "/v2.5/auth/login" {
		// Need phoneNumber only
		rgx := regexp.MustCompile(`\bphoneNumber=`)
		return rgx.MatchString(string(requestBody))
	}

	for _, protectedRoute := range []string{
		"/v2.5/auth/sign-up",

		// Email editing
		//"/v2.5/user/email",

		// Phone number amending
		//"/v2.5/phone",
		//"/v2.5/phone/retry",
	} {
		if uri == protectedRoute {
			return true
		}
	}

	return false
}

func sendErrorResponse(ctx filters.FilterContext, statusCode int, message string) {
	b, _ := json.Marshal(
		errorResponse{
			Error: errorObj{
				Status: statusCode,
				Details: errorObjDetails{
					Message: message,
				},
			},
		},
	)

	header := http.Header{}
	header.Set("Content-Type", "application/json")

	ctx.Serve(
		&http.Response{
			StatusCode: statusCode,
			Header:     header,
			Body:       io.NopCloser(bytes.NewBufferString(string(b))),
		},
	)
}

func sendUpgradeResponse(ctx filters.FilterContext, platform Platform, locale string) {
	var ls map[Platform]map[string]string
	err := json.Unmarshal(langStrings, &ls)
	if err != nil {
		log.Println(err)
	}

	message := ls[platform][locale]

	b, _ := json.Marshal(
		struct {
			Status int `json:"status"`
			Error  struct {
				Type    int    `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}{
			Status: http.StatusUpgradeRequired,
			Error: struct {
				Type    int    `json:"type"`
				Message string `json:"message"`
			}{
				Type:    0,
				Message: message,
			},
		},
	)

	header := http.Header{}
	header.Set("Content-Type", "application/json")

	ctx.Serve(
		&http.Response{
			StatusCode: http.StatusUpgradeRequired,
			Header:     header,
			Body:       io.NopCloser(bytes.NewBufferString(string(b))),
		},
	)
}

func env() string {
	switch os.Getenv("ENVIRONMENT") {
	case production:
		return production
	case dev:
		return dev
	default:
		return local
	}
}

func calculateRequestNonce(r *http.Request, challenge string) (string, error) {
	r.URL.Scheme = "https"
	switch env() {
	case production:
		r.URL.Host = "api.muzzapi.com"
	case dev:
		r.URL.Host = "api.dev.muzzapi.com"
	default:
		r.URL.Host = "localhost"
	}

	usingBody := true
	bodyBuf, readBodyErr := io.ReadAll(r.Body)
	if readBodyErr != nil {
		return "", fmt.Errorf("cannot read body: %w", readBodyErr)
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf)) // Set the body back to the original so it can be read again later
	dataToHash := bytes.NewBuffer(bodyBuf).Bytes()

	// If there's no request body use the URL as the data to hash
	if len(dataToHash) == 0 {
		usingBody = false
		dataToHash = []byte(r.URL.String())
	}

	fmt.Printf("dataToHash is body data: %v\n", usingBody)
	if !usingBody {
		fmt.Printf("dataToHash: %s\n", string(dataToHash))
	}
	hash := sha256.New()
	hash.Write(dataToHash)
	hSum := hash.Sum(nil)
	fmt.Printf("sha256 of dataToHash: %x\n", hSum)
	b64 := base64.URLEncoding.EncodeToString(hSum)
	fmt.Printf("b64 of above: %s\n", b64)
	hash.Reset()
	hash.Write([]byte(base64.URLEncoding.EncodeToString([]byte(challenge)) + b64))
	hSum2 := hash.Sum(nil)
	fmt.Printf("above prepended with challenge and sha256: %x\n", hSum2)
	fmt.Printf("b64 of above: %s\n", base64.URLEncoding.EncodeToString(hSum2))

	fmt.Println(strings.Repeat("#", 80))
	return base64.URLEncoding.EncodeToString(hSum2), nil
}

func getAppIdForIos() (string, bool) {
	return "5MRWH833JE.com.muzmatch.muzmatch.alpha", false
	return "5MRWH833JE.com.muzmatch.muzmatch", true
}

func figureOutLocale(accept string) string {
	var matcher = language.NewMatcher([]language.Tag{
		language.English,
		language.Arabic,
		language.Bengali,
		language.German,
		language.Spanish,
		language.Persian,
		language.French,
		// language.Hindi, // TODO: the translations we have aren't even close
		language.Indonesian,
		language.Italian,
		language.Malay,
		language.Dutch,
		language.Russian,
		language.Turkish,
		language.Urdu,
	})
	tag, _ := language.MatchStrings(matcher, "", accept)
	locale := tag.String()
	if len(locale) > 5 {
		locale = strings.Split(locale, "-")[0]
	}

	return locale
}
