package main

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/mod/semver"
	"golang.org/x/text/language"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/zalando/skipper/filters"
)

var _ filters.Filter = (*attestationFilter)(nil)

//go:embed lang.json
var langStrings []byte

type attestationFilter struct {
	repo       *repo
	googlePlay googlePlayIntegrityServiceClient
	appStore   appStore
	logger     *slog.Logger
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

func (a attestationFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	// request bodies can only be read once
	requestBody, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(requestBody))

	if !isProtectedRoute(r, requestBody) {
		// Not a protected route, skip
		return
	}

	// Fetch headers we'll need
	deviceUDID := r.Header.Get("udid")
	userAgent := r.Header.Get("user-agent")
	appVersion := r.Header.Get("appVersion")
	authorizationHeader := r.Header.Get("authorization")
	bypassHeader := r.Header.Get("x-muzz-bypass-device-integrity-check")
	encodedKeyId := r.Header.Get("x-keyid")             // iOS only
	encodedAssertation := r.Header.Get("x-assertation") // iOS only

	// Determine platform
	var isAndroid = androidUserAgent.MatchString(r.Header.Get("user-agent"))
	var isIOS bool
	for _, rgx := range iOSUserAgents {
		if rgx.MatchString(userAgent) {
			isIOS = true
			break
		}
	}

	// Check there is a UDID
	if deviceUDID == "" {
		sendErrorResponse(ctx, http.StatusForbidden, "Missing UDID in request")
		return
	}

	// Check there is an app version
	if appVersion == "" {
		sendErrorResponse(ctx, http.StatusForbidden, "Missing app version in request")
		return
	}

	// Enforce minimum versions of apps
	var platform Platform
	switch {
	case isAndroid:
		platform = PlatformAndroid

		if !strings.HasPrefix(appVersion, "v") {
			appVersion = "v" + appVersion
		}

		// It always does, but just to be safe
		if strings.HasSuffix(appVersion, "a") {
			appVersion = strings.TrimSuffix(appVersion, "a")
		}

		// TODO: the body is a bit trickier, plus needs to be localised
		if semver.Compare(appVersion, minimumAndroidVersion) < 0 {
			accept := ctx.Request().Header.Get("Accept-Language")
			sendUpgradeResponse(ctx, platform, figureOutLocale(accept))
		}

		// skip android for now
		bypassHeader = "true"
	case isIOS:
		platform = PlatformIos

		if !strings.HasPrefix(appVersion, "v") {
			appVersion = "v" + appVersion
		}

		if semver.Compare(appVersion, minimumIosVersion) < 0 {
			accept := ctx.Request().Header.Get("Accept-Language")
			sendUpgradeResponse(ctx, platform, figureOutLocale(accept))
		}
	default:
		sendErrorResponse(ctx, http.StatusForbidden, "Invalid OS")
		return
	}

	// Is there a bypass header (used for automated tests and in Postman)?
	if bypassHeader != "" {
		return
	}

	// TODO: error handling
	existingAppAttestation, _ := a.repo.GetAttestationForUDID(deviceUDID)

	// If there is no authorization header, or there is no existing app attestation record in the database, issue the challenge
	if existingAppAttestation == nil || authorizationHeader == "" {
		// Generate 128 random bytes
		buf := make([]byte, 128)
		_, _ = rand.Read(buf)

		err := a.repo.CreateAttestationForUDID(
			deviceUDID,
			[]byte(base64.URLEncoding.EncodeToString(buf)),
			platform,
			ctx.Request().Header,
			string(requestBody),
		)
		if err != nil {
			return
		}

		header := http.Header{}
		header.Set("Content-Type", "application/json")
		header.Set("WWW-Authenticate", "Integrity")

		b, _ := json.Marshal(
			struct {
				Challenge string `json:"challenge"`
			}{
				Challenge: base64.URLEncoding.EncodeToString(buf),
			},
		)

		ctx.Serve(
			&http.Response{
				StatusCode: 480, // 480 is the response we've agreed with the apps teams to initiate integrity check
				Header:     header,
				Body:       io.NopCloser(bytes.NewBufferString(string(b))),
			},
		)
		return
	}

	// Has the app sent an error code instead
	if isIOS {
		authorizationHeader = strings.TrimPrefix(authorizationHeader, "Error ")

		switch authorizationHeader {
		case "featureUnsupported":
			fallthrough
		case "invalidInput":
			fallthrough
		case "invalidKey":
			fallthrough
		case "serverUnavailable":
			fallthrough
		case "unknownSystemFailure":
			existingAppAttestation.DeviceErrorCode = authorizationHeader
			err := a.repo.UpdateAttestationForUDID(existingAppAttestation)
			if err != nil {
				a.logger.Error("update device error code", "err", err)
			}

			// TODO: issue a captcha challenge
			return
		}
	}

	if isAndroid {
		switch authorizationHeader {
		case "API_NOT_AVAILABLE":
			fallthrough
		// Make sure that Integrity API is enabled in Google Play Console.
		// Ask the user to update Google Play Store.
		case "NETWORK_ERROR": // Ask them to retry
			fallthrough
		case "PLAY_STORE_NOT_FOUND": // Ask the user to install or enable Google Play Store.
			fallthrough
		case "PLAY_STORE_VERSION_OUTDATED": // Ask the user to update Google Play Store.
			fallthrough
		case "PLAY_STORE_ACCOUNT_NOT_FOUND": // Ask the user to sign in to the Google Play Store.
			fallthrough
		case "CANNOT_BIND_TO_SERVICE": // Ask the user to update the Google Play Store.
			fallthrough
		case "PLAY_SERVICES_NOT_FOUND": // Ask the user to install or enable Play Services.
			fallthrough
		case "PLAY_SERVICES_VERSION_OUTDATED": // Ask the user to update Google Play services.
			fallthrough
		case "TOO_MANY_REQUESTS": // Retry with an exponential backoff.
			fallthrough
		case "GOOGLE_SERVER_UNAVAILABLE": // Retry with an exponential backoff.
			fallthrough
		case "CLIENT_TRANSIENT_ERROR": // Retry with an exponential backoff.
			fallthrough
		case "INTERNAL_ERROR": // Retry with an exponential backoff.
			fallthrough
		case "APP_NOT_INSTALLED": // Pass error to API and do nothing else
			fallthrough
		case "NONCE_TOO_SHORT": // Pass error to API and do nothing else
			fallthrough
		case "NONCE_TOO_LONG": // Pass error to API and do nothing else
			fallthrough
		case "NONCE_IS_NOT_BASE64": // Pass error to API and do nothing else
			fallthrough
		case "CLOUD_PROJECT_NUMBER_IS_INVALID": // Pass error to API and do nothing else
			fallthrough
		case "APP_UID_MISMATCH": // Pass error to API and do nothing else
			fallthrough
		// The following are catch-all errors reported by the client
		case "INVALID_ERROR": // Google client SDK returned an error but didn't match an expected error code
			fallthrough
		case "ERROR": // There was some non-Google SDK error that stopped authorization being granted
			existingAppAttestation.DeviceErrorCode = authorizationHeader
			err := a.repo.UpdateAttestationForUDID(existingAppAttestation)
			if err != nil {
				a.logger.Error("update challenge response", "err", err)
			}

			// TODO: issue a captcha challenge
			return
		}
	}

	// Authorization header is present, lets validate
	if !strings.HasPrefix(authorizationHeader, "Integrity ") {
		sendErrorResponse(ctx, http.StatusForbidden, "Missing integrity authorization header")
		return
	}
	authorizationHeader = strings.TrimPrefix(authorizationHeader, "Integrity ")

	// Check for empty authorization header
	if authorizationHeader == "" {
		sendErrorResponse(ctx, http.StatusForbidden, "Empty authorization header")
		return
	}

	// Set the challenge response we received
	existingAppAttestation.ChallengeResponse = authorizationHeader
	err := a.repo.UpdateAttestationForUDID(existingAppAttestation)
	if err != nil {
		a.logger.Error("update challenge response", "err", err)
	}

	// Base64 decode the header value
	challengeResponse, base64decodeErr := base64.URLEncoding.DecodeString(authorizationHeader)
	if base64decodeErr != nil {
		sendErrorResponse(ctx, http.StatusForbidden, "Could not decode challenge response from base64 URL encoding")
		return
	}

	// Calculate the hash
	var base64encodedChallenge string // TODO: base64.URLEncoding.EncodeToString(existingAppAttestation.challenge))
	serverNonce, serverNonceErr := calculateRequestNonce(ctx.Request(), base64encodedChallenge)
	if serverNonceErr != nil {
		sendErrorResponse(ctx, http.StatusInternalServerError, "Failed to calculate server nonce")
		return
	}

	switch {
	case isAndroid:
		verdict := a.googlePlay.validate(challengeResponse, serverNonce, existingAppAttestation)
		err = a.repo.UpdateAttestationForUDID(existingAppAttestation)
		if err != nil {
			a.logger.Error("update challenge response", "err", err)
		}

		if verdict == integritySuccess {
			return // All good, proceed
		}

		if verdict == integrityUnevaluated {
			// TODO: Captcha challenge
			return
		}

		// Integrity failed, throw an error
		sendErrorResponse(ctx, http.StatusForbidden, "Integrity check failed")

	case isIOS:
		if encodedAssertation == "" {
			sendErrorResponse(ctx, http.StatusForbidden, "Empty x-assertation header")
			return
		}
		if encodedKeyId == "" {
			sendErrorResponse(ctx, http.StatusForbidden, "Empty x-keyid header")
			return
		}

		verdict, validateErr := a.appStore.validate(authorizationHeader, existingAppAttestation.Challenge, encodedKeyId, existingAppAttestation)
		if validateErr != nil {
			existingAppAttestation.MuzzError = validateErr.Error()
		}

		err = a.repo.UpdateAttestationForUDID(existingAppAttestation)
		if err != nil {
			a.logger.Error("update challenge response", "err", err)
		}

		if verdict == integritySuccess {
			return // All good, proceed
		}

		if verdict == integrityUnevaluated {
			// TODO: Captcha challenge
			return
		}

		// Integrity failed
		sendErrorResponse(ctx, http.StatusForbidden, "Integrity check failed")
		return
	}

	// All good, continue
	return
}

func (a attestationFilter) Response(_ filters.FilterContext) {}

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
