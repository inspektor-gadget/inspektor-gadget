# IG Benchmarks

### Runnign the benchmarks

1. Make sure you have the `benchmarks.yaml` file configured correctly.
2. Run the benchmarks using the following command:

```bash
$ make benchmarks-test
```

It'll generate a `test_results_<date>.csv` file with the results of the
benchmarks.

### Analyzing the results

You can analyze the results using the Jupyter notebook
`benchmarks_analysis.ipynb`. You can run it in different applications supporting
Jupyter notebooks, such as VS Code with the Jupyter extension, JupyterLab, or
Jupyter Notebook. Or you can generate an HTML report from the notebook using the
following command:

```bash
$ INTPUT_FILE=path_to_csv_filemake make gen-html
```
