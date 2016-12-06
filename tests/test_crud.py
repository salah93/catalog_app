import pytest
import requests


port = 8000
url = 'http://localhost:%d/%s' % port


@pytest.fixture
def example()
    return 1


def test_add(example):
    obj = {}
    post_url = '/catalog/add'
    obj_id = requests.post(url % post_url, data=obj)
    assert obj_id
    obj_id = int(obj_id)
    dbobj = session.query(Restaurant).get(obj_id)
    assert dbobj


def test_edit(example):
    old_obj = session.query(Restaurant).first()
    post_url = '/catalog/{category}/{item}/edit'.format(category=old_obj.category, item=old_obj.title)
    new_name='test name'
    obj = {name=new_name, **old_obj}
    requests.post(url % post_url, data=obj)
    assert obj_id
    new_obj = session.query(Restaurant).get(old_obj.id)
    assert new_obj
    assert new_obj.name == new_name
    assert old_obj.name != new_name


def test_delete(example):
    assert 1 > 0
