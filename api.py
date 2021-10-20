#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging
from optparse import OptionParser
import uuid

from class_fields import (
    Field,
    ArgumentsField,
    BirthDayField,
    CharField,
    ClientIDsField,
    DateField,
    EmailField,
    GenderField,
    PhoneField,
)
import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}


class RequestData:
    def __init__(self, args):
        if args:
            errors = []
            field_names = [k for k, v in self.generate_dict_field_items()]

            for f in field_names:
                try:
                    setattr(self, f, args.get(f))
                except ValueError as e:
                    errors.append(str(e))

            if errors:
                raise ValueError(", ".join(errors))
        else:
            raise ValueError("Empty " + self.__class__.__name__ + ".")

    def generate_dict_field_items(self):
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Field):
                yield k, v

    def validate(self):
        pass


class ClientInterestsHandler(RequestData):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def do(self, request, context, store):
        context["nclients"] = len(self.client_ids)
        interests = {cid: scoring.get_interests(store, cid) for cid in self.client_ids}
        return interests

    def validate(self):
        pass


class OnlineScoreHandler(RequestData):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        if (
            (self.phone is None or self.email is None)
            and (self.first_name is None or self.last_name is None)
            and (self.gender is None or self.birthday is None)
        ):
            raise ValueError("Arguments must have at least one valid pair")

    def do(self, request, context, store):
        context["has"] = []
        for k, v in self.__class__.__dict__.items():
            if isinstance(v, Field) and getattr(self, k) is not None:
                context["has"].append(k)

        if request.is_admin:
            score = 42
        else:
            score = scoring.get_score(
                store,
                self.phone,
                self.email,
                birthday=self.birthday,
                gender=self.gender,
                first_name=self.first_name,
                last_name=self.last_name,
            )
        return {"score": score}


class MethodRequest(RequestData):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        bytes = (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")
        digest = hashlib.sha512(bytes).hexdigest()
    else:
        bytes = (request.account + request.login + SALT).encode("utf-8")
        digest = hashlib.sha512(bytes).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    request_router = {
        "online_score": OnlineScoreHandler,
        "clients_interests": ClientInterestsHandler,
    }

    try:
        request = MethodRequest(request.get("body"))
        logging.debug("Request parsed correctly")
    except ValueError as e:
        return str(e), INVALID_REQUEST
    if not check_auth(request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    try:
        method = request_router[request.method](request.arguments)
        method.validate()
    except KeyError as e:
        return "Method {} not found".format(request.method), INVALID_REQUEST
    except ValueError as e:
        return str(e), INVALID_REQUEST
    response = method.do(request, ctx, store)
    return response, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"code": code, "response": response}
        else:
            r = {"code": code, "error": response or ERRORS.get(code, "Unknown Error")}
        context.update(r)
        logging.info(context)
        json_str = json.dumps(r)
        json_str = json_str.encode("utf-8")
        self.wfile.write(json_str)
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(
        filename=opts.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    logging.info("Stopped server")
