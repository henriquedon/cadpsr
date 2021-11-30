import pendulum
from cadpsr import db
from cadpsr.models import Colaborador, Entidade, Pessoa
from werkzeug.security import generate_password_hash, check_password_hash



agora = str(pendulum.now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss'))
data_nasc = '1990-01-01'
status = 'ATIVO'

#Lista de Entidades Fictícias da Região de SBC e Sto. André
entidades = [['CRAS SANTO ANDRE - CENTRO', 'ATENDIMENTO', 'cras.stoandre.centro@cadpsr.com','00000000', 'Av. Ramiro Colleoni, xx', '00000000', 'SANTO ANDRE', 'SP'],
             ['CRAS SBC - CENTRO', 'ATENDIMENTO', 'cras.sbc.centro@cadpsr.com','0000000000', 'Av. Brigadeiro Faria Lima, xx', '00000000', 'SAO BERNARDO DO CAMPO', 'SP'],
             ['CREAS SANTO ANDRE', 'ATENDIMENTO', 'creas.sbc@cadpsr.com', '00000000', 'Av.Pereira Barreto, xx', '00000000', 'SANTO ANDRE', 'SP'],
             ['CREAS SBC', 'ATENDIMENTO', 'creas.sbc@cadpsr.com', '0000000000', 'Av. Rendenção, xx', '00000000', 'SAO BERNARDO DO CAMPO', 'SP']
             ]

#Gravação das Entidades Fictícias no Banco de Dados
for i in range(4):
    entidade = Entidade(status='ATIVO',
                        nome=entidades[i][0],
                        tipo_etd=entidades[i][1],
                        email=entidades[i][2],
                        telefone=entidades[i][3],
                        endereco=entidades[i][4],
                        cep=entidades[i][5],
                        cidade=entidades[i][6],
                        uf=entidades[i][7],
                        data_criacao=agora,
                        criado_por='dev-gr6')
    db.session.add(entidade)
    db.session.commit()

senha = input('Digite sua nova senha: ')
senha = generate_password_hash(senha) # hash da senha expressa entre parênteses -- entre aspas simples!
print('Hash de senha gerado com sucesso.')

# Lista de Colaboradores
colaboradores = [['Dev Grupo 6 Polo SBC', '11111111111', data_nasc ,'gestor@cadpsr.com', senha,'GESTOR','5']]


colaborador = Colaborador(status='ATIVO',
                          nome_civil=colaboradores[0][0],
                          nome_social=colaboradores[0][0],
                          cpf=colaboradores[0][1],
                          data_nascimento=colaboradores[0][2],
                          email=colaboradores[0][3],
                          senha=colaboradores[0][4],
                          tipo_clb=colaboradores[0][5],
                          lotacao=colaboradores[0][6],
                          data_criacao=agora,
                          criado_por='dev-gr6')
db.session.add(colaborador)
db.session.commit()
colaborador = Colaborador.query.get(1)

print('As Entidades e a crendencial do gestor foi criadas com sucesso.')
print()
print(f'E-mail/login de acesso: {colaborador.email}')
print()
