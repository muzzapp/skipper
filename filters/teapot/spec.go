package teapot

import (
	"github.com/zalando/skipper/filters"
)

var Spec filters.Spec = (*teapotSpec)(nil)

type teapotSpec struct{}

func (s *teapotSpec) Name() string {
	return "teapot"
}

func (s *teapotSpec) CreateFilter(_ []interface{}) (filters.Filter, error) {
	tf := &teapotFilter{}
	tf.loadServices()
	tf.loadTeapots()

	return tf, nil
}
