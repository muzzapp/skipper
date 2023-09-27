package device_integrity

import (
	"regexp"
)

const (
	minimumAndroidVersion = "v7.41.0"
	minimumIosVersion     = "v7.51.0"
	production            = "production"
	dev                   = "dev"
	local                 = "local"
)

type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIos     Platform = "ios"
)

var (
	iOSUserAgents = []*regexp.Regexp{
		regexp.MustCompile(`^Muzz/[7-8]\.\d+\.\d+ \(com\.muzmatch\.muzmatch; build:\d+; iOS \d+\.\d+\.\d+\) Alamofire/\d+\.\d+\.\d+$`),
		regexp.MustCompile(`^MuzzAlpha/[7-8]\.\d+\.\d+ \(com\.muzmatch\.muzmatch\.alpha; build:\d+; iOS \d+\.\d+\.\d+\) Alamofire/\d+\.\d+\.\d+$`),
		regexp.MustCompile(`^MuzzTestsUI-Runner/\d+\.\d+ \(com\.muzmatch\.muzmatchUITests\.xctrunner; build:\d+; iOS \d+\.\d+\.\d+\) Alamofire/\d+\.\d+\.\d+$`),
	}
	androidUserAgent = regexp.MustCompile(`^okhttp/\d+\.\d+\.\d+$`)
)
