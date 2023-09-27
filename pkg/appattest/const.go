package appattest

type IntegrityEvaluation int

const (
	IntegrityUnevaluated IntegrityEvaluation = iota
	IntegrityFailure
	IntegritySuccess
)
