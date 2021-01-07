.PHONY:init freeze test run clean
init:
	pip install -r requirements.txt
freeze:
	pip freeze > requirements.txt
fmt:
	autopep8 -i -r  -a -a -a --experimental -v dnscrawler/
	autopep8 --list-fixes 
test:
	python -m unittest discover
clean:
	rm -rf run/data/*
	find . -path ./venv -prune -false -o  -type d -name "__pycache__" -exec rm -rf {} +