#!/usr/bin/python3
# -*- coding: utf-8 -*-
from optparse import OptionParser
import yaml
from flask import Flask, jsonify
from flask import request
from flask import make_response
from flask import redirect, url_for
from flask import send_from_directory
from werkzeug.utils import secure_filename
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from functools import wraps,update_wrapper
import time
import os
import random
import tarfile
import tempfile
from wallet import Wallet

def mk_cors(resp):
    if 'HTTP_ORIGIN' in request.environ and request.environ['HTTP_ORIGIN']:
        resp.headers.add('Access-Control-Allow-Origin', request.environ['HTTP_ORIGIN'])
    elif request.referrer:
        r = request.referrer.split('/')
        rs = ''
        if len(r) > 2:
            rs = r[0] + '//' + r[2]
        else:
            rs = r[0]
        resp.headers.add('Access-Control-Allow-Origin', rs)
    resp.headers.add('Access-Control-Allow-Credentials', 'true')
    resp.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    resp.headers.add('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS')
    resp.headers.add('Access-Control-Allow-Headers', 'Authorization')
    resp.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return resp


class CrossKeeper(object):
    def crossdomain(self):
        def decorator(f):
            @wraps(f)
            def wrapped_function(*args, **kwargs):
                resp = make_response(f(*args, **kwargs))
                return mk_cors(resp)
            f.provide_automatic_options = False
            return update_wrapper(wrapped_function, f)

        return decorator

app = Flask(__name__)

class TokenKeeper(object):
    def verify_auth_token(self, token):
        print('top of verify_auth_token')
        print(token)
        s = Serializer(app.config['SECRET_KEY'])
        try:
            self.data = s.loads(token)
        except SignatureExpired:
            return False # valid token, but expired
        except BadSignature:
            return False # invalid token
        return self.data['ip'] == request.remote_addr

    def require_api_token(self, api_method):
        print('top of require_api_token')

        @wraps(api_method)

        def check_api_key(*args, **kwargs):
            print('check_api_key')
            apikey = request.args.get('token')
            if apikey and verify_auth_token(apikey):
                return api_method(*args, **kwargs)
            if 'token' in request.cookies:
                apikey = request.cookies['token']
                if self.verify_auth_token(apikey):
                    return api_method(*args, **kwargs)

            print("generate_auth_token")
            self.data = { 'ip': request.remote_addr, 'salt': random.randint(0,10000000), 'st': 1 }
            return api_method(*args, **kwargs)

        return check_api_key

    def generate_auth_token(self):
        # self.data = { 'ip': request.remote_addr, 'st': 1 }
        s = Serializer(app.config['SECRET_KEY'], expires_in = 6000)
        return s.dumps(self.data)  #constant object id


token_keeper = TokenKeeper()

ck = CrossKeeper()


# W = Wallet(app.config['DEPLOY_YAML'], app.config['PROVIDER'] )

def allowed_file(filename):
    return True


@app.route('/api/<path:code>', methods=['OPTIONS'])
@ck.crossdomain()
def wallet_options(code):
    # response = jsonify({'result': 'OK'})
    return ""

@app.route('/api/v1/wallet/<business>', methods=['GET'])
@token_keeper.require_api_token
@ck.crossdomain()
def wallet_get(business):
    token_body = token_keeper.generate_auth_token().decode('ascii')
    token_keeper.data.pop('ip')
    response = make_response(jsonify(token_keeper.data))
    response.set_cookie('token',value=token_body)
    return response

@app.route('/api/v2/wallet/<business>', methods=['GET'])
@token_keeper.require_api_token
@ck.crossdomain()
def wallet_get2(business):
    token_body = token_keeper.generate_auth_token().decode('ascii')
    token_keeper.data.pop('ip')
    (ether_price, token_price) = W.get_price(business)
    token_keeper.data['token_price'] = token_price
    token_keeper.data['ether_price'] = ether_price

    response = make_response(jsonify(token_keeper.data))
    response.set_cookie('token',value=token_body)
    return response

@app.route('/api/v2/wallet/<business>', methods=['POST'])
@token_keeper.require_api_token
@ck.crossdomain()
def wallet_post2(business):
    if 'changed' in token_keeper.data:
        token_keeper.data.pop('changed')
    if token_keeper.data['st'] == 1:
        content = request.get_json(silent=True, force=True)
        if not content or not 'wallet' in content:
            response = make_response(jsonify({'error': '1'}), 500)
            return response
        elif W.another_active_session(content['wallet'], token_keeper.data['ip'], token_keeper.data['salt']):
            response = make_response("Unauthorized Access")
            response = mk_cors(response)
            response.status_code = 401
            return response
        else:
            print(content['wallet'])
            token_keeper.data['wallet'] = content['wallet']


            pravo_tokens = W.get_pravo_tokens(content['wallet'])

            token_keeper.data['pravo_tokens'] = pravo_tokens
            token_keeper.data['root_contract'] = W.root_contract()

            token_keeper.data['st'] = 2
            token_keeper.data['changed'] = 1
    elif token_keeper.data['st'] == 2:
        if W.payment_ok(token_keeper.data['wallet']):
            # prevent multiple contracts ??
            W.create_contract(business, token_keeper.data['wallet'])
            # we have to wait !!!
            created = 0
            step = 0
            while not created and step < 100:
                time.sleep(2)
                (created, contract_number) = W.get_contract_number(token_keeper.data['wallet'])
                print("step is {}".format(step))
                step += 1
            if created:
                token_keeper.data['contract_number'] = contract_number
                token_keeper.data['st'] = 3
                token_keeper.data['changed'] = 1
        else:
            time.sleep(2)

    elif token_keeper.data['st'] == 3:
        print("file load")
        uploaded_files = request.files.getlist("myfiles[]")

        # put to a tar file
        tmpdir = tempfile.mkdtemp()
        ocr_in_dir = os.path.join(tmpdir, 'OCR_in')
        os.mkdir(ocr_in_dir)
        print("tmpdir is ", tmpdir)
        print("email is ", request.form['email'])
        token_keeper.data['email'] = request.form['email']

        for a_file in uploaded_files:
            print(a_file.filename)

            if a_file.filename:
                a_file.save(os.path.join(ocr_in_dir, a_file.filename))

        os.chdir(tmpdir)
        tarfname = str(token_keeper.data['contract_number'])[-20:] + '.tgz'

        with tarfile.open(os.path.join(app.config['UPLOAD_FOLDER'], tarfname), "w:gz") as tar:
            tar.add(".")

        # pass files
        W.start_job(token_keeper.data['contract_number'], tarfname)

        token_keeper.data['st'] = 4
        token_keeper.data['changed'] = 1

    elif token_keeper.data['st'] >= 4:
        stage = W.get_current_link_num(token_keeper.data['contract_number'])
        # can be zero !!
        token_keeper.data['st'] = 5 + stage
        token_keeper.data['changed'] = 1

    print(token_keeper.data)

    token_body = token_keeper.generate_auth_token().decode('ascii')
    for only_in_token in ['ip', 'salt']:
        token_keeper.data.pop(only_in_token)
    response = make_response(jsonify(token_keeper.data))
    response.set_cookie('token',value=token_body)
    return response


@app.route('/api/v1/wallet/<business>', methods=['POST'])
@token_keeper.require_api_token
@ck.crossdomain()
def wallet_post(business):
    if token_keeper.data['st'] == 1:
        content = request.get_json(silent=True, force=True)
        if not content or not 'wallet' in content:
            response = make_response(jsonify({'error': '1'}), 500)
            return response
        elif W.another_active_session(content['wallet'], token_keeper.data['ip'], token_keeper.data['salt']):
            response = make_response("Unauthorized Access")
            response = mk_cors(response)
            response.status_code = 401
            return response
        else:
            print(content['wallet'])
            token_keeper.data['wallet'] = content['wallet']


            pravo_tokens = W.get_pravo_tokens(content['wallet'])
            (ether_price, token_price) = W.get_price(business)
            needed_tokens = 0
            if pravo_tokens < token_price:
                needed_tokens = token_price - pravo_tokens

            token_keeper.data['token_price'] = token_price
            token_keeper.data['ether_price'] = ether_price

            token_keeper.data['pravo_tokens'] = pravo_tokens
            token_keeper.data['root_contract'] = W.root_contract()

            token_keeper.data['needed_tokens'] = needed_tokens
            token_keeper.data['ether_to_pay'] = ether_price

            token_keeper.data['st'] = 2

    elif token_keeper.data['st'] == 2:
        # have to check payment
        token_keeper.data['st'] = 3

    elif token_keeper.data['st'] == 3:
        if W.payment_ok(token_keeper.data['wallet']):
            W.create_contract(business, token_keeper.data['wallet'])
            token_keeper.data['st'] = 4

    elif token_keeper.data['st'] == 4:
        (created, contract_number) = W.get_contract_number(token_keeper.data['wallet'])
        if created:
            token_keeper.data['contract_number'] = contract_number
            token_keeper.data['st'] = 5

    elif token_keeper.data['st'] == 5:
        print("file load")
        uploaded_files = request.files.getlist("file[]")

        # put to a tar file
        tmpdir = tempfile.mkdtemp()
        ocr_in_dir = os.path.join(tmpdir, 'OCR_in')
        os.mkdir(ocr_in_dir)
        print("tmpdir is ", tmpdir)

        for a_file in uploaded_files:
            print(a_file.filename)

            if a_file.filename:
                a_file.save(os.path.join(ocr_in_dir, a_file.filename))

        os.chdir(tmpdir)
        tarfname = str(token_keeper.data['contract_number'])[-20:] + '.tgz'

        with tarfile.open(os.path.join(app.config['UPLOAD_FOLDER'], tarfname), "w:gz") as tar:
            tar.add(".")

        # pass files
        W.start_job(token_keeper.data['contract_number'], tarfname)

        token_keeper.data['st'] = 6

    elif token_keeper.data['st'] >= 6:
        stage = W.get_current_link_num(token_keeper.data['contract_number'])
        token_keeper.data['st'] = 7 + stage

    print(token_keeper.data)

    token_body = token_keeper.generate_auth_token().decode('ascii')
    for only_in_token in ['ip', 'salt']:
        token_keeper.data.pop(only_in_token)
    response = make_response(jsonify(token_keeper.data))
    response.set_cookie('token',value=token_body)
    return response


@app.route('/l/<id>', methods=['PUT'])
@ck.crossdomain()
def link_put(id):
    print("id=%s" % id)
    response = jsonify({'result': 'OK'})
    return(response)


@app.route('/a/<filename>', methods=['OPTIONS'])
@ck.crossdomain()
def area_options(filename):
    response = jsonify({'result': 'OK'})
    return response

@app.route('/a', methods=['POST'])
@ck.crossdomain()
def area_post():
    # check if the post request has the file part
    if 'file' not in request.files:
        print('No file part')
        return(make_response(jsonify({'error': '1'}), 500))
    file = request.files['file']
    # if user does not select file, browser also
    # submit a empty part without filename
    if file.filename == '':
        print('No selected file')
        return(make_response(jsonify({'error': '1'}), 500))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        response = jsonify({'result': 'OK'})
        return(response)

@app.route('/a/<filename>', methods=['PUT'])
@ck.crossdomain()
def area_put(filename):
    # check if the post request has the file part
    if filename == '':
        print('No selected file')
        return(make_response(jsonify({'error': '1'}), 500))
    if allowed_file(filename):
        sfilename = secure_filename(filename)
        sjfilename = os.path.join(app.config['UPLOAD_FOLDER'], sfilename)
        print(sjfilename)
        with open(sjfilename, 'wb+') as f:
            f.write(request.stream.read())
    response = jsonify({'result': 'OK'})
    return(response)

@app.route('/a/<filename>')
@ck.crossdomain()
def area_get(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

if __name__ == '__main__':

    usage = """
    %prog [options]
        Run PRAVO API
        example: $ ./pravo_api.py --deploy=/path/to/deploy/yaml
    """


    parser = OptionParser(usage=usage)

    parser.add_option("--deploy", "--deploy-yaml", "--yaml", dest="yaml_fname", default="../contracts/deploy.yaml",
        help="path to deploy.yaml file")
    (options, args) = parser.parse_args()


    app.config['JSON_AS_ASCII'] = False
    app.config['DEPLOY_YAML'] = options.yaml_fname
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    with open(app.config['DEPLOY_YAML'], 'r') as f:
        y = yaml.load(f)

    app.config['PROVIDER'] = y['settings']['provider']
    app.config['UPLOAD_FOLDER'] = y['settings']['upload_folder']
    app.config['SECRET_KEY'] = y['settings']['secret_key']

    W = Wallet(app.config['DEPLOY_YAML'], app.config['PROVIDER'] )


    app.run(debug=True, threaded=True, host='0.0.0.0', port=8008) #, ssl_context=('cert.pem', 'key.pem'))
