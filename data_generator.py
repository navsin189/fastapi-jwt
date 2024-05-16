if __name__ == "__main__":
    '''
    It generate tons of fake users.
    I was using it initally just to test some functionality.
    Now the JWT is in place, so I don't need it anymore.
    '''
    import json
    from faker import Faker
    fake = Faker()

    USERS_JSON_FILE = 'users.json'
    fake_user_data_dict = {}
    for _ in range(1001):
        email = fake.email(domain='fake.com')
        name = fake.name()
        password = fake.password(length=8,upper_case=True,lower_case=True,special_chars=True)
        if email not in fake_user_data_dict.keys():
            fake_user_data_dict[email] = {'name': name,'password':password}

    with open(USERS_JSON_FILE,'w') as cred:
        cred.write(json.dumps(fake_user_data_dict))
