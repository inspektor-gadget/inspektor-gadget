# BENCHMARKS_TESTS_PARAMS can be used to pass additional parameters locally e.g
# BENCHMARKS_TESTS_PARAMS="-run TestBenchmarks/trace_dns" make benchmarks-test
.PHONY: benchmarks-test
benchmarks-test:
	go test -exec sudo -v ./... -benchmark -timeout 0 $$BENCHMARKS_TESTS_PARAMS

.PHONY: gen-html
gen-html:
	jupyter nbconvert --to html --execute benchmarks_analysis.ipynb
