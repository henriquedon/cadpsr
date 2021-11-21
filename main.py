from cadpsr import app, db
from cadpsr.models import Colaborador, Entidade, Pessoa, Acesso

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Colaborador': Colaborador, 'Entidade': Entidade, 'Pessoa': Pessoa, 'Acesso': Acesso}
