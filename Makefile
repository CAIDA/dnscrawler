.PHONY:init freeze test
init:
	pip install -r requirements.txt
freeze:
	pip freeze > requirements.txt
test:
	python -m unittest discover