package teapot

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/joho/godotenv"
	"github.com/zalando/skipper/filters"
	"golang.org/x/text/language"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type teapotSpec struct{}

type teapotRoute []struct {
	URI     string `json:"uri"`
	Note    string `json:"note,omitempty"`
	IsRegex bool   `json:"regex,omitempty"`
}

type teapotService struct {
	Name   string      `json:"name"`
	Routes teapotRoute `json:"routes"`
}

type teapotConfig struct {
	Enabled         bool              `json:"enabled"`
	Services        []string          `json:"services"`
	IgnoreCountries []string          `json:"ignoreCountries"`
	OnlyCountries   []string          `json:"onlyCountries"`
	Title           map[string]string `json:"title"`
	Message         map[string]string `json:"message"`
	EndsAt          time.Time         `json:"endsAt"`
	ExtendBy        int               `json:"extendBy"`
}

type teapotFilter struct {
	NextLoad     time.Time
	Services     []teapotService
	ServicesHash string
	Teapots      []teapotConfig
	TeapotsHash  string
}

type teapotError struct {
	Status int            `json:"status"`
	Error  teapotResponse `json:"error"`
}

type teapotResponse struct {
	Type                        int    `json:"type"`
	Title                       string `json:"title"`
	Message                     string `json:"message"`
	PredictedUptimeTimestampUTC string `json:"predictedUptimeTimestampUTC"`
	Global                      bool   `json:"global"`
}

func NewTeapot() filters.Spec {
	godotenv.Load()
	return &teapotSpec{}
}

func (s teapotSpec) Name() string {
	return "teapot"
}

func (s teapotSpec) CreateFilter(config []interface{}) (filters.Filter, error) {
	var teapotFilter teapotFilter

	teapotFilter.LoadServices()
	teapotFilter.LoadTeapots()

	return &teapotFilter, nil
}

func (f *teapotFilter) FetchS3File(bucket string, key string, target string) error {
	sess := session.Must(session.NewSession())
	downloader := s3manager.NewDownloader(sess)

	// Create a file to write the S3 Object contents to.
	file, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create file %q, %v", target, err)
	}

	// Write the contents of S3 Object to the file
	_, err = downloader.Download(file, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to download file, %v", err)
	}

	return nil
}

func (f *teapotFilter) Md5File(target string) (string, error) {
	file, _ := os.Open(target)

	hash := md5.New()
	_, err := io.Copy(hash, file)
	file.Close()
	if err != nil {
		return "", fmt.Errorf("failed to get MD5 file: %s", target)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (f *teapotFilter) LoadServices() {
	target := "/tmp/services.json"
	err := f.FetchS3File(os.Getenv("TEAPOT_S3_BUCKET"), os.Getenv("TEAPOT_S3_SERVICES_KEY"), target)
	if err != nil {
		fmt.Printf("Error fetching services.json: %s", err)
		return
	}

	// Only import if the hash is different
	md5file, err := f.Md5File(target)
	if err != nil || md5file == f.ServicesHash {
		return
	}
	f.ServicesHash = md5file

	data, _ := os.ReadFile(target)
	//fmt.Printf("%s\n", data)
	err = json.Unmarshal(data, &f.Services)
	if err != nil {
		fmt.Printf("Error reading services.json: %s", err)
		return
	}
	//fmt.Printf("%+v\n", f.Services)
}

func (f *teapotFilter) LoadTeapots() {
	target := "/tmp/teapots.json"
	err := f.FetchS3File(os.Getenv("TEAPOT_S3_BUCKET"), os.Getenv("TEAPOT_S3_TEAPOTS_KEY"), target)
	if err != nil {
		fmt.Printf("Error fetching teapots.json: %s", err)
		return
	}

	// Only import if the hash is different
	md5file, err := f.Md5File(target)
	if err != nil || md5file == f.TeapotsHash {
		return
	}
	f.TeapotsHash = md5file

	data, _ := os.ReadFile(target)
	//fmt.Printf("%s\n", data)
	err = json.Unmarshal(data, &f.Teapots)
	if err != nil {
		fmt.Printf("Error reading services.json: %s", err)
		return
	}
	//fmt.Printf("%+v\n", f.Teapots)
}

func (f *teapotFilter) CalculateCountry(ctx filters.FilterContext) string {
	cloudFrontCountry := strings.TrimSpace(ctx.Request().Header.Get("CloudFront-Viewer-Country"))

	// If behind a Cloudfront CDN
	if cloudFrontCountry != "" {
		return cloudFrontCountry
	}

	cloudFlareCountry := strings.TrimSpace(ctx.Request().Header.Get("CF-IPCountry"))

	// If behind a Cloudflare CDN
	if cloudFlareCountry != "" {
		return cloudFlareCountry
	}

	return "GB"
}

func (f *teapotFilter) SendTeapotMessage(ctx filters.FilterContext, teapot teapotConfig, global bool) {
	var languageTags []language.Tag
	for lang := range teapot.Message {
		languageTags = append(languageTags, language.Make(lang))
	}

	var matcher = language.NewMatcher(languageTags)
	accept := ctx.Request().Header.Get("Accept-Language")
	tag, _ := language.MatchStrings(matcher, "", accept)
	locale := tag.String()

	if len(locale) > 5 {
		locale = strings.Split(locale, "-")[0]
	}

	var titleLanguageTags []language.Tag
	for lang := range teapot.Title {
		titleLanguageTags = append(titleLanguageTags, language.Make(lang))
	}

	matcher = language.NewMatcher(titleLanguageTags)
	tag, _ = language.MatchStrings(matcher, "", accept)
	titleLocale := tag.String()

	if len(titleLocale) > 5 {
		titleLocale = strings.Split(titleLocale, "-")[0]
	}

	ctx.Logger().Infof("Locale: %s", locale)

	message := teapot.Message[locale]
	if strings.Contains(teapot.Message[locale], "%s") {
		message = fmt.Sprintf(teapot.Message[locale], teapot.EndsAt.UTC().Format("3:04pm UTC"))
	}
	jsonResponse, _ := json.Marshal(&teapotError{
		Status: 418,
		Error: teapotResponse{
			Message:                     message,
			Title:                       teapot.Title[titleLocale],
			PredictedUptimeTimestampUTC: teapot.EndsAt.UTC().Format(time.RFC3339),
			Global:                      global,
		},
	})
	ctx.Serve(&http.Response{
		StatusCode: http.StatusTeapot,
		Header: http.Header{
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{strconv.Itoa(len(string(jsonResponse)))},
		},
		Body: io.NopCloser(bytes.NewBufferString(string(jsonResponse))),
	})
}

func (f *teapotFilter) Request(ctx filters.FilterContext) {
	if time.Now().After(f.NextLoad) {
		ctx.Logger().Infof(
			"Teapot Reload required",
		)

		f.NextLoad = time.Now().Add(30 * time.Second)
		go f.LoadServices()
		go f.LoadTeapots()
	}

	ctx.Logger().Infof(
		"Teapot Route: %s. Next Load: %s",
		ctx.Request().RequestURI,
		f.NextLoad.String(),
	)

	// Get the country code
	CountryCode := f.CalculateCountry(ctx)
	ctx.Logger().Infof("Calculate Country: %s", CountryCode)

	// Check for teapot
	for _, teapot := range f.Teapots {
		if teapot.Enabled {
			// Check if we have gone over the estimated time
			if teapot.EndsAt.Before(time.Now().UTC()) {
				teapot.EndsAt = time.Now().Round(time.Duration(teapot.ExtendBy) * time.Minute).Add(time.Duration(teapot.ExtendBy) * time.Minute)
			}

			// Check if we have ignored this country
			ignored := false
			for _, Country := range teapot.IgnoreCountries {
				if Country == CountryCode {
					ignored = true
					break
				}
			}

			if ignored {
				// We are ignoring this country - continue to next teapot
				continue
			}

			// Check if we are only teapotting for this country
			if len(teapot.OnlyCountries) > 0 {
				found := false
				for _, Country := range teapot.OnlyCountries {
					if Country == CountryCode {
						found = true
						break
					}
				}

				if !found {
					// This country isn't in the list - continue to next teapot
					continue
				}
			}

			ctx.Logger().Infof("Teapot enabled\n")
			ctx.Logger().Infof("%+v\n", teapot)

			for _, TService := range teapot.Services {
				for _, service := range f.Services {
					if service.Name == TService {
						ctx.Logger().Infof(">>>>>> %s\n", service.Name)
						for _, route := range service.Routes {
							if route.IsRegex {
								match, _ := regexp.MatchString(route.URI, ctx.Request().RequestURI)
								if match {
									ctx.Logger().Infof("Matched route %s\n", route.URI)

									f.SendTeapotMessage(ctx, teapot, TService == "all")
									return
								}
							} else {
								if strings.HasSuffix(route.URI, "*") {
									if strings.HasPrefix(ctx.Request().RequestURI, route.URI[0:len(route.URI)-1]) {
										ctx.Logger().Infof("Matched route %s\n", route.URI)

										f.SendTeapotMessage(ctx, teapot, TService == "all")
										return
									}
								} else if ctx.Request().RequestURI == route.URI {
									ctx.Logger().Infof("Matched route %s\n", route.URI)

									f.SendTeapotMessage(ctx, teapot, TService == "all")
									return
								}
							}
						}
					}
				}
			}
		}
	}
}

func (f *teapotFilter) Response(ctx filters.FilterContext) {}
