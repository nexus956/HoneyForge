.PHONY: test run dashboard report clean

test:
	python3 -m unittest discover -t .

run:
	python3 -m honeyforge run --dashboard

dashboard:
	python3 -m honeyforge dashboard

report:
	python3 -m honeyforge report

clean:
	rm -rf data/ build/ dist/ *.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
