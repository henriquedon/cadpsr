import pendulum
from cadpsr import db
from cadpsr.models import Colaborador, Entidade, Pessoa
from werkzeug.security import generate_password_hash, check_password_hash



agora = str(pendulum.now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss'))
data_nasc = '1990-01-01'
status = 'ATIVO'

#Lista de Entidades Fictícias da Região de SBC e Sto. André
entidades = [['CRAS SBC - CENTRO', 'ATENDIMENTO', 'cras.sbc.centro@cadpsr.com','0000000000', 'Av. Brigadeiro Faria Lima, xx', '00000000', 'SAO BERNARDO DO CAMPO', 'SP'],
             ['CREAS SBC', 'ATENDIMENTO', 'creas.sbc@cadpsr.com', '0000000000', 'Av. Rendenção, xx', '00000000', 'SAO BERNARDO DO CAMPO', 'SP'],
             ['CRAS SANTO ANDRE - CENTRO', 'ATENDIMENTO', 'cras.stoandre.centro@cadpsr.com','00000000', 'Av. Ramiro Colleoni, xx', '00000000', 'SANTO ANDRE', 'SP'],
             ['CREAS SANTO ANDRE', 'ATENDIMENTO', 'creas.sbc@cadpsr.com', '00000000', 'Av.Pereira Barreto, xx', '00000000', 'SANTO ANDRE', 'SP']]

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

senha = generate_password_hash('teste') # hash da senha expressa entre parênteses -- entre aspas simples!

# Lista de Colaboradores
colaboradores = [['João Fictício', '11111111111', data_nasc ,'gestor@cadpsr.com', senha,'GESTOR','GESTORA-SP'],
                 ['Ada Lovelace','22222222222',data_nasc, 'ada.lovelace@cadpsr.com', senha, 'GERENTE', 'CRAS SBC - CENTRO'],
                 ['Hipatia de Alexandria','33333333333',data_nasc, 'hipatia.alexandria@cadpsr.com', senha, 'GERENTE', 'CREAS SBC'],
                 ['Tales de Mileto','44444444444',data_nasc, 'tales.mileto@cadpsr.com', senha, 'GERENTE', 'CRAS SANTO ANDRE - CENTRO'],
                 ['John von Rambo','55555555555',data_nasc, 'john.rambo@cadpsr.com', senha, 'GERENTE','CREAS SANTO ANDRE']]

for i in range(5):
    colaborador = Colaborador(status='ATIVO',
                              nome_civil=colaboradores[i][0],
                              nome_social=colaboradores[i][0],
                              cpf=colaboradores[i][1],
                              data_nascimento=colaboradores[i][2],
                              email=colaboradores[i][3],
                              senha=colaboradores[i][4],
                              tipo_clb=colaboradores[i][5],
                              lotacao=colaboradores[i][6],
                              data_criacao=agora,
                              criado_por='dev-gr6')
    db.session.add(colaborador)
    db.session.commit()

print('A criação de novos Colaboradores e Entidades foi efetudada com sucesso!')
