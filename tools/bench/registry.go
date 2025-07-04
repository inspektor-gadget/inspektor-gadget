package main

var (
	registry = map[string]GeneratorFactory{}
)

func RegisterGenerator(name string, factory GeneratorFactory) {
	if _, exists := registry[name]; exists {
		panic("generator already registered: " + name)
	}
	registry[name] = factory
}

func GetGenerator(name string) (GeneratorFactory, bool) {
	factory, exists := registry[name]
	if !exists {
		return nil, false
	}
	return factory, true
}
