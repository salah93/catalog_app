# CRUD with items
demonstrate full stack web app with full crud functionality with item app

to run app locally, create a virtual environment and install the requirements, then hit python :)

```
git clone https://github.com/salah93/catalog_app.git
cd catalog_app
pip install -U pip, virtualenv
mkdir ~/.virtualenvs && virtualenv ~/.virtualenvs/item_app
. ~/.virtualenvs/item_app/bin/activate
pip install -r requirements.txt
python app.py
```

once you run the app you will be able to visit it in your web browser on your local machine at `'http://localhost:8002'`


# Tests
This app has been tested with the following versions of python:
+ 3.5
+ 2.7

to test run `py.test` in `tests` directory
