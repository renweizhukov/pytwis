init:
	pip install -r requirements.txt

test:
	python3.6 -m unittest -v

test_coverage:
	pip install coverage
	python3.6 -m coverage run -m unittest
	python3.6 -m coverage report
	
test_coverage_html:
	pip install coverage
	python3.6 -m coverage run -m unittest
	python3.6 -m coverage html
	
.PHONY: init test test_coverage test_coverage_html