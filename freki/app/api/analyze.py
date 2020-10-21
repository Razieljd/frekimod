"""
    Freki - malware analysis tool

    Copyright (C) 2020 Freki authors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from flask_restplus import Resource
from flask import request

from app.core.yaraanalysis import YaraAnalysis
from app.core.hashes import Hashes
from app.core.strings import Strings
from app.core.utils import get_basic_information, save_file
from app.models import RuleModel
from werkzeug.datastructures import FileStorage

from . import api, ns_general, upload_parser, get_bytes, get_sha1, token_required
from app import db
from sqlalchemy.exc import DataError
import yara
import json
import ast

analyze_parser = api.parser()
analyze_parser.add_argument("text", required=True)
analyze_parser.add_argument("rule", required=True, type=dict, action='append')

ALLOWED_EXTENSIONS = ['txt']

@ns_general.route("/analyze/text", methods=["POST"])
class AnalyzeText(Resource):
    """Fetches basic information about a file."""

    @api.doc(responses={201: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @api.expect(analyze_parser)
    def post(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """
        args = analyze_parser.parse_args()
        text = args["text"]
        ruleEntrada = args["rule"]
        rulesYara = {}
        rulesResponse = []
        def mycallback(data):
            self.dataMatch = data["matches"]
            return yara.CALLBACK_CONTINUE
        for rul in ruleEntrada:
            _id=rul["rule_id"]
            rule = RuleModel.query.get(_id)
            if rule:
                nombre = rule.name
                regla = rule.rule
                rulesYara[nombre] = regla
                yaraMatch = yara.compile(source=regla)
                yaraMatch.match(data=text, callback=mycallback)
                rulesResponse.append({"rule_id": rule.id, "matched":self.dataMatch})
            else:
                return {"Error id":"Rule id " + str(rul["rule_id"]) +" no exite"}, 400
        
            
        return {"status": "ok", "results": rulesResponse},201
        

analyze_file_parser = api.parser()
@ns_general.route("/analyze/file", methods=["POST"])
class AnalyzeFile(Resource):
    """Fetches basic information about a file."""

    @api.doc(responses={201: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @api.expect(analyze_file_parser)
    def post(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """
        if 'file' not in request.files:
            return {"Error": "ingresa un archivo en archivo"}, 400

        file = request.files['file']
        
        filename = file.filename
        print(filename, flush=True)
        if filename == '':
            return {"Error": "ingresa un archivo un archivo"}, 400
            
        extension = filename.rsplit(".", 1)
        

        
        if extension in ALLOWED_EXTENSIONS:
            return {"Error": "extención no permitida ingrese un archivo .txt"}, 400
        
        
        data = dict(request.form)
        print(data,flush=True)
        print(file,flush=True)
        ruleEntrada = data["rules"].split(",")
        print(ruleEntrada,flush=True)
        rulesYara = {}
        rulesResponse = []
        def mycallback(data):
            print(data,flush=True)
            self.dataMatch = data["matches"]
            print(self.dataMatch,flush=True)
            return yara.CALLBACK_CONTINUE
        for rul in ruleEntrada:
            try:
                rul = int(rul)
            except:
                return {"Error": "dato de la regla no permitida"}, 400
            rule = RuleModel.query.get(rul)
            if rule:
                nombre = rule.name
                regla = rule.rule
                rulesYara[nombre] = regla
                yaraMatch = yara.compile(source=regla)
                yaraMatch.match(data=file.read(), callback=mycallback)
                print(self.dataMatch,flush=True)
                rulesResponse.append({"rule_id": rule.id, "matched":self.dataMatch})
            else:
                return {"Error id":"Rule id " + str(rul["rule_id"]) +" no exite"}, 400
        
            
        return {"status": "ok", "results": rulesResponse},201


        