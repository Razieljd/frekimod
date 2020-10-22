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

from app.core.yaraanalysis import YaraAnalysis
from app.core.hashes import Hashes
from app.core.strings import Strings
from app.core.utils import get_basic_information, save_file
from app.models import RuleModel

from . import api, ns_general, upload_parser, get_bytes, get_sha1, token_required
from app import db
from sqlalchemy.exc import DataError
import yara

rule_parser = api.parser()
rule_parser.add_argument("name", required=True)
rule_parser.add_argument("rule", required=True)

@ns_general.route("/rule", methods=["POST"])
class Rule(Resource):
    """Fetches basic information about a file."""

    @api.doc(responses={201: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @api.expect(rule_parser)
    def post(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """
        args = rule_parser.parse_args()
        name = args["name"]
        ruleEntrada = args["rule"]

        rule = RuleModel.query.filter_by(name=name).first()
        if rule:
            return {"Error":"Nombre de la regla ya creada"}, 400

        try:
            yara.compile(source=ruleEntrada)
        except:
            return {"Error":"regla invalida"}, 400
        
        rule = RuleModel(name=name, rule=ruleEntrada)
        db.session.add(rule)

        try:
            db.session.commit()
            rule = RuleModel.query.filter_by(name=name).first()
            return {"id":rule.id, "name": rule.name, "rule": rule.rule}, 201
        except DataError:
            return {"Error":"en la base de datos"}, 400


@ns_general.route("/rules", methods=["GET"])
class Rules(Resource):
    """Fetches basic information about a file."""

    @api.doc(responses={201: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    def get(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """


        rules = RuleModel.query.order_by(RuleModel.id).all()
        respuesta =[]
        
        for rule in rules:
            respuesta.append({"id":rule.id, "name": rule.name, "rule": rule.rule})
        
        print(respuesta,flush=True)
        
        return {"rules": respuesta},201
        
            
        #return {"id":rule.id, "name": rule.name, "rule": rule.rule}, 201
        
