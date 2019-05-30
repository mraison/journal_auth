import json

def test_requesting_jwt(client):
    # Test creating a real doctor, successfully

    # Note: Flask chokes if you pass in an inline dict; must use json.dumps()
    rv = client.post('/create_user',
                     data=json.dumps(
                         dict(
                             username='joe',
                             password='pass'
                         )
                     ),
                     content_type='application/json')

    assert rv.status_code == 200

    data = json.loads(rv.data)
    for field in ['ID']:
        assert field in data

    # assert len(data['access_token']) > 0
