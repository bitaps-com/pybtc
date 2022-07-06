FLAGS=

flake:
	flake8 pybtc tests

test:
	py.test -s $(FLAGS) ./tests/

vtest:
	py.test -s -v $(FLAGS) ./tests/

cov cover coverage:
	py.test -s -v  --cov-report term --cov-fail-under=1 --cov-report html --cov pybtc ./tests

clean:
	rm -rf `find . -name __pycache__`
	rm -f `find . -type f -name '*.py[co]' `
	rm -f `find . -type f -name '*~' `
	rm -f `find . -type f -name '.*~' `
	rm -f `find . -type f -name '@*' `
	rm -f `find . -type f -name '#*#' `
	rm -f `find . -type f -name '*.orig' `
	rm -f `find . -type f -name '*.rej' `
	rm -rf coverage
	rm -rf htmlcov
	rm -rf build
	rm -rf dist


doc:
	make -C docs
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: all flake test vtest cov clean doc