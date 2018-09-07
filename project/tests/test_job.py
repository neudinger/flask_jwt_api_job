import time
import json
import unittest

import unittest
from project.server import db
from project.server.models import User
from project.tests.base import BaseTestCase
from project.tests.test_auth import login_user, register_user


def send_job(self, user):
    return self.client.post(
        '/users/{}/offers'.format(1),
        headers=dict(
            Authorization='Bearer ' + json.loads(
                user.data.decode()
            )['auth_token']
        ),
        data=json.dumps(dict(
            user_id=1,
            title="Titre",
            description="description"
        )),
        content_type='application/json',
    )


def user_data(self, user):
    return self.client.get(
        '/auth/status',
        headers=dict(
            Authorization='Bearer ' + json.loads(
                user.data.decode()
            )['auth_token']
        )
    )


class TestJobOffer(BaseTestCase):
    def test_add_job(self):
        with self.client:
            user = register_user(self, 'joe@gmail.com', '123456')
            response = self.client.post(
                '/users/{}/offers'.format(1),
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        user.data.decode()
                    )['auth_token']
                ),
                data=json.dumps(dict(
                    user_id=1,
                    title="Titre",
                    description="description"
                )),
                content_type='application/json',
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully added.')
            self.assertEqual(response.status_code, 200)

    def test_show_jobs(self):
        user = register_user(self, 'joe@gmail.com', '123456')
        send_job(self, user)
        userdata = json.loads(user_data(self, user).data.decode())
        response = self.client.get(
            '/users/{}/offers'.format(userdata["data"]["user_id"]),
            headers=dict(
                Authorization='Bearer ' + json.loads(
                    user.data.decode()
                )['auth_token']
            ),
            data=json.dumps(dict(
                user_id=userdata["data"]["user_id"],
                title="Titre",
                description="description"
            )),
            content_type='application/json',
        )
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertEqual(response.status_code, 200)

    def test_show_job(self):
        user = register_user(self, 'joe@gmail.com', '123456')
        job = send_job(self, user)
        userdata = json.loads(user_data(self, user).data.decode())
        response = self.client.get(
            '/users/{}/offers/{}'.format(userdata["data"]["user_id"], 1),
            headers=dict(
                Authorization='Bearer ' + json.loads(
                    user.data.decode()
                )['auth_token']
            ),
            data=json.dumps(dict(
                user_id=userdata["data"]["user_id"],
                title="Titre",
                description="description"
            )),
            content_type='application/json',
        )
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertEqual(response.status_code, 200)

    def test_edit_job(self):
        user = register_user(self, 'joe@gmail.com', '123456')
        job = send_job(self, user)
        userdata = json.loads(user_data(self, user).data.decode())
        response = self.client.put(
            '/users/{}/offers/{}'.format(userdata["data"]["user_id"], 1),
            headers=dict(
                Authorization='Bearer ' + json.loads(
                    user.data.decode()
                )['auth_token']
            ),
            data=json.dumps(dict(
                user_id=userdata["data"]["user_id"],
                title="Titre info",
                description="description changé"
            )),
            content_type='application/json',
        )
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertEqual(response.status_code, 200)

    def test_delete_job(self):
        user = register_user(self, 'joe@gmail.com', '123456')
        job = send_job(self, user)
        userdata = json.loads(user_data(self, user).data.decode())
        response = self.client.delete(
            '/users/{}/offers/{}'.format(userdata["data"]["user_id"], 1),
            headers=dict(
                Authorization='Bearer ' + json.loads(
                    user.data.decode()
                )['auth_token']
            )
        )
        data = json.loads(response.data.decode())
        self.assertTrue(data['status'] == 'success')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()