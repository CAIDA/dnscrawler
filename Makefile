.PHONY:init freeze test run clean
init:
	pip install -r requirements.txt
freeze:
	pip freeze > requirements.txt
test:
	python -m unittest discover
clean:
	rm -rf run/data/*