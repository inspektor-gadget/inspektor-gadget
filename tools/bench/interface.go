package main

type GeneratorFactory func(string) (Generator, error)

type Generator interface {
	Start() error
	Stop() error
}
