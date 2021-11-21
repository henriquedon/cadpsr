import pendulum
from werkzeug.security import generate_password_hash, check_password_hash
from cadpsr import db
from cadpsr.models import Colaborador, Entidade, Pessoa


id_clb = int(input('Informe o ID do colaborador: '))

c = Colaborador.query.get(id_clb)
senha = 'teste'
senha_hash = generate_password_hash(senha)
c.senha = senha_hash

print(f'A senha do colaborador IDº {id_clb} foi restaurada com sucesso')
print(f'Colaborador: {c.nome_civil}')
print(f'     E-mail: {c.email}')
print(f'    Lotacao: {c.lotacao}')
print(f'      Senha: {senha}')
