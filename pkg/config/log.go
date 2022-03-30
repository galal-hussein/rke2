package config

type Log struct {
	VLevel          int
	VModule         string
	LogFile         string
	AlsoLogToStderr bool
	Debug           bool
}
