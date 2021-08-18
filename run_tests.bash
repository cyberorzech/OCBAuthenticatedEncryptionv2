coverage run --source=./src -m pytest tests/tests.py
coverage report -m
coverage html -d tests/html_report