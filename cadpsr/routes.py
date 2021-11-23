from datetime import timedelta
from secrets import token_hex
from flask import session, render_template, flash
from flask import redirect, url_for, request
from flask_login import login_user, logout_user
from flask_login import current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from pendulum import now
from cadpsr import app, db
from cadpsr.forms import LoginForm
from cadpsr.dicionarios import campos_cad, questionario
from cadpsr.funcoes import carimbo_data, lista_para_str
from cadpsr.models import Colaborador, Pessoa, Acesso


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    #flash('AVISO IMPORTANTE: ao prosseguir, esteja ciente que, temporariamente, nós armazenamos apenas dados necessários para o funcionamento de nosso Site.', category='success')


    form = LoginForm()
    if form.validate_on_submit():
        colaborador = Colaborador.query.filter_by(
            email=form.email.data).first()
        if colaborador is None or not colaborador.verifica_senha_hash(form.senha.data):
            flash('E-mail/Senha inválido(a)!', category='error')
            return redirect(url_for('login'))
        if colaborador.status == 'INATIVO':
            flash(
                'Acesso negado. Por favor, notifique sua chefia imediata.', category='error')
            return redirect(url_for('login'))

        acesso = Acesso(data_hora=now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss'),
                        id_clb=colaborador.id,
                        nome_clb=colaborador.nome_civil,
                        status_clb=colaborador.status,
                        lotacao_clb=colaborador.lotacao
                        )
        db.session.add(acesso)
        db.session.commit()

        login_user(colaborador)
        if current_user.status == 'INICIO' or current_user.status == 'REDEF':
            flash(
                'Para acessar outras áreas do sistema, você precisa alterar sua senha.', category='error')
            return redirect(url_for('perfil'))
        proxima_pagina = request.args.get('next')
        if not proxima_pagina or url_parse(proxima_pagina).netloc != '':
            proxima_pagina = url_for('index')
        return redirect(url_for('index'))
    return render_template('login.html', titulo='Login - CadPSR', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@app.route('/index')
@login_required
def index():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    cadpsr_versao = 'Ver. 1.5'

    return render_template("index.html", titulo='Home :: CadPSR', cadpsr_versao=cadpsr_versao,
                                                                  campos_cad=campos_cad)


@app.route('/colaboradores', methods=['GET', 'POST'])
@login_required
def colaboradores():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    titulo = 'Consulta CLB - CadPSR'
    busca = None
    acessos = None
    colaborador = None
    colaboradores = None
    clb_entidade = len(Colaborador.query.filter_by(lotacao=current_user.lotacao).all())
    clb_total = len(Colaborador.query.all())

    if request.method == 'POST':
        if request.form.get('dado') == '' or None:
            return redirect(url_for('colaboradores'))
        busca = True
        dado = request.form.get('dado').lower()
        campo = request.form.get('campo')

        if "'" not in dado or '"' not in dado:

            if dado == '.acesso' or dado == '.acesso1' or dado == '.acesso2' or dado == '.acesso3' or dado == '.acesso4':
                if current_user.tipo_clb == 'GESTOR':
                    if dado == '.acesso':
                        acessos = Acesso.query.order_by(Acesso.id_acesso.desc()).all()
                        #acessos = Acesso.query.all()
                    else:
                        acessos = Acesso.query.filter_by(lotacao_clb=dado[7]).all()

                elif dado == '.acesso':
                    acessos = Acesso.query.filter_by(lotacao_clb=current_user.lotacao).all()

                if not acessos:
                    acessos = None
                    flash("A consulta não obteve resultados.", category="error")
                    return redirect('/colaboradores')
                return render_template('/colaboradores.html', acessos=acessos,
                                                              busca=busca,
                                                              campos_cad=campos_cad,
                                                              dado=dado,
                                                              clb_entidade=clb_entidade,
                                                              clb_total=clb_total,
                                                              colaborador=colaborador,
                                                              colaboradores=colaboradores,
                                                              titulo=titulo
                                                              )

            if dado == '.t' or dado == '.e1' or dado == '.e2' or dado == '.e3' or dado == '.e4':
                colaborador = None
                if current_user.tipo_clb == 'GESTOR':
                    if dado == '.t':
                        colaboradores = Colaborador.query.all()
                    else:

                        colaboradores = Colaborador.query.filter_by(lotacao=dado[2]).all()

                elif dado == '.t':
                    colaboradores = Colaborador.query.filter_by(lotacao=current_user.lotacao).all()

                if not colaboradores:
                    colaboradores = None
                    flash("A consulta não obteve resultados.", category="error")
                    return redirect('/colaboradores')
                return render_template('/colaboradores.html', acessos=acessos,
                                                              busca=busca,
                                                              campos_cad=campos_cad,
                                                              dado=dado,
                                                              clb_entidade=clb_entidade,
                                                              clb_total=clb_total,
                                                              colaborador=colaborador,
                                                              colaboradores=colaboradores,
                                                              titulo=titulo
                                                              )
            if campo == 'NOME':
                colaborador = Colaborador.query.filter(Colaborador.nome_civil.like('%' + dado + '%')).first()
                
            elif campo == 'ID':
                if dado.isdigit():
                    colaborador = Colaborador.query.filter_by(id=int(dado)).first()
                else:
                    flash('Utilize apenas números na consulta por ID.', category='error')
                    return redirect('/colaboradores')
            else:
                if dado.isdigit():
                    colaborador = Colaborador.query.filter_by(cpf=dado).first()
                else:
                    flash('Utilize apenas números na consulta por CPF.', category='error')
                    return redirect('/colaboradores')

            if colaborador and busca == True:

                if colaborador.tipo_clb == 'GESTOR':
                    flash('Cadastro não localizado.', category='error')
                    return redirect(url_for('colaboradores'))

                if colaborador.cpf == current_user.cpf:
                    flash('Cadastro não localizado.', category='error')
                    return redirect(url_for('colaboradores'))

                if colaborador.id == current_user.id:
                    flash('Cadastro não localizado.', category='error')
                    return redirect(url_for('colaboradores'))

                if current_user.tipo_clb == 'GERENTE':
                    if current_user.lotacao != colaborador.lotacao:
                        flash('Cadastro não localizado.', category='error')
                        return redirect(url_for('colaboradores'))

                return render_template('colaboradores.html', acessos=acessos,
                                                             busca=busca,
                                                             campos_cad=campos_cad,
                                                             dado=dado,
                                                             colaborador=colaborador,
                                                             colaboradores=None,
                                                             clb_entidade=clb_entidade,
                                                             clb_total=clb_total,
                                                             titulo=titulo
                                                             )
            else:
                busca = None
                flash("Cadastro não localizado.", category="error")
                return redirect('/colaboradores')

        else:
            flash(
                "Utilize apenas letras ou número para efetuar a consulta.", category="error")
            return render_template('colaboradores.html', acessos=acessos,
                                                         busca=None,
                                                         titulo=titulo
                                                         )


    return render_template('colaboradores.html', busca=busca,
                                                 campos_cad=campos_cad,
                                                 clb_entidade=clb_entidade,
                                                 clb_total=clb_total,
                                                 titulo=titulo
                                                 )


@app.route('/pessoas', methods=['GET', 'POST'])
@login_required
def pessoas():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    titulo = 'Consulta PSR - CadPSR'
    busca = None
    psr_entidade = len(Pessoa.query.filter_by(entidade_referencia=current_user.lotacao).all())
    psr_total = len(Pessoa.query.all())

    if request.method == 'POST':
        if request.form.get('dado') == '' or None:
            return redirect(url_for('pessoas'))
        busca = True
        dado = request.form.get('dado')
        campo = request.form.get('campo')

        if '"' not in dado or "'" not in dado:
            if dado == '.t' or dado == '.e1' or dado == '.e2' or dado == '.e3' or dado == '.e4':
                pessoa = None
                pessoas = None
                if current_user.tipo_clb == 'GESTOR':
                    if dado == '.t':
                        #pessoas = Pessoa.query.order_by(Pessoa.id.desc()).all()
                        pessoas = Pessoa.query.all()
                    else:
                        pessoas = Pessoa.query.filter_by(entidade_referencia=dado[2]).all()
                        if len(pessoas ) == 0:
                            pessoas = None

                elif dado == '.t':
                    pessoas = Pessoa.query.filter_by(entidade_referencia=current_user.lotacao).all()

                if not pessoas:
                    flash("A consulta não obteve resultados.", category="error")
                    return redirect('/pessoas')

                return render_template('/pessoas.html', busca=busca,
                                                        campos_cad=campos_cad,
                                                        dado=dado,
                                                        pessoa=pessoa,
                                                        pessoas=pessoas,
                                                        psr_entidade=psr_entidade,
                                                        psr_total=psr_total,
                                                        titulo=titulo
                                                        )

            if campo == 'NOME':
                pessoa = Pessoa.query.filter(
                    Pessoa.nome_civil.like('%' + dado + '%')).first()
            elif campo == 'ID':
                if dado.isdigit():
                    pessoa = Pessoa.query.filter_by(id=int(dado)).first()
                else:
                    flash(
                        'Ao selecionar ID como filtro para pesquisa, utilize apenas números.', category='error')
                    return redirect('/pessoas')
            else:
                if dado.isdigit():
                    pessoa = Pessoa.query.filter_by(cpf=dado).first()
                else:
                    flash(
                        'Ao selecionar CPF como filtro para pesquisa, utilize apenas números.', category='error')
                    return redirect('/pessoas')

            if pessoa:
                dn = pessoa.data_nascimento.split('-')
                nascimento = f'{dn[2]}/{dn[1]}/{dn[0]}'
                return render_template('/pessoas.html', busca=busca,
                                                        campos_cad=campos_cad,
                                                        pessoa=pessoa,
                                                        pessoas=None,
                                                        psr_entidade=psr_entidade,
                                                        psr_total=psr_total,
                                                        titulo=titulo,
                                                        )
            else:
                busca = None
                flash("Cadastro não localizado.", category="error")
                return redirect('/pessoas')

        else:
            flash(
                "Utilize apenas letras ou número para efetuar a consulta.", category="error")
            return redirect('')

    return render_template('/pessoas.html', busca=busca,
                                            campos_cad=campos_cad,
                                            psr_entidade=psr_entidade,
                                            psr_total=psr_total,
                                            titulo=titulo,
                                            )


@app.route('/cadastro_clb/<clb_id>', methods=['GET', 'POST'])
@login_required
def cadastro_clb(clb_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    titulo = 'Dados Cadastrais - Colaborador(a)'
    colaborador = Colaborador.query.get(clb_id)

    if current_user.id == colaborador.id:
        flash('Você não tem permissão para visualizar/editar seu próprio cadastro', category='error')
        return redirect('/colaboradores')

    if current_user.tipo_clb == 'GERENTE' and current_user.lotacao != colaborador.lotacao:
        flash('Acesso não autorizado.', category='error')
        return redirect(url_for('colaboradores'))

    if not colaborador:
        flash('Cadastro não localizado.', category='error')
        return redirect(url_for('colaboradores'))

    if colaborador.data_criacao:
        data_criacao = carimbo_data(colaborador.data_criacao)
    else:
        data_criacao = ''
    if colaborador.data_atualizacao:
        data_atualizacao = carimbo_data(colaborador.data_atualizacao)
    else:
        data_atualizacao = ''

    return render_template('cadastro_clb.html', campos_cad=campos_cad,
                                                colaborador=colaborador,
                                                data_criacao=data_criacao,
                                                data_atualizacao=data_atualizacao,
                                                titulo=titulo
                                                )


@app.route('/cadastro_psr/<int:psr_id>', methods=['GET', 'POST'])
@login_required
def cadastro_psr(psr_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    pessoa = Pessoa.query.get(psr_id)

    if not pessoa:
        flash('Cadastro não encontrado.', category="error")
        return redirect('/pessoas')

    titulo = 'Cadastro PSR'
    titulo_body_1 = 'Dados Cadastrais - PSR'
    titulo_body_2 = pessoa.nome_civil

    if pessoa.data_criacao:
        data_criacao = carimbo_data(pessoa.data_criacao)
    else:
        data_criacao = ''
    if pessoa.data_atualizacao:
        data_atualizacao = carimbo_data(pessoa.data_atualizacao)
    else:
        data_atualizacao = ''

    return render_template('/cadastro_psr.html',
                           campos_cad=campos_cad,
                           colaborador=current_user,
                           data_atualizacao=data_atualizacao,
                           data_criacao=data_criacao,
                           pessoa=pessoa,
                           questionario=questionario,
                           titulo=titulo,
                           titulo_body_1=titulo_body_1,
                           titulo_body_2=titulo_body_2
                           )


@app.route('/edicao_clb/<clb_id>', methods=['GET', 'POST'])
@login_required
def edicao_clb(clb_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    colaborador = Colaborador.query.get(clb_id)

    if not colaborador:
        flash('Colaborador(a) não encontrado!', category='error')
        return redirect(url_for('colaboradores'))

    titulo = 'Dados Cadastrais - Colaborador'

    if current_user.tipo_clb == 'GERENTE' and current_user.lotacao != colaborador.lotacao:
        flash('Acesso negado.', category='error')
        return redirect(url_for('colaboradores'))

    if colaborador.data_criacao:
        data_criacao = carimbo_data(colaborador.data_criacao)
    else:
        data_criacao = ''
    if colaborador.data_atualizacao:
        data_atualizacao = carimbo_data(colaborador.data_atualizacao)
    else:
        data_atualizacao = ''

    if request.method == 'POST':

        cpf = request.form.get('cpf')
        email = request.form.get('email')
        nome_civil = request.form.get('nome_civil')
        nome_social = request.form.get('nome_social')
        if nome_social is None or nome_social == '':
            nome_social = nome_civil
        data_nascimento = request.form.get('data_nascimento')
        email = request.form.get('email')
        tipo_clb = request.form.get('tipo_clb')
        lotacao = request.form.get('lotacao')
        modificado_por = current_user.id

        # VERIFICAÇÃO DE ENTRADA DE DADOS

        if nome_civil is not None:
            if len(nome_civil) > 60:
                flash('O campo Nome Civil não pode conter mais de  caracteres.', category='error')
                return redirect('/novo_clb')

        if nome_social is not None:
            if len(nome_social) > 60:
                flash('O campo Nome Social não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_clb')

        if data_nascimento is not None:
            if len(data_nascimento) > 10:
                flash('O campo "Data de Nascimento" não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_clb')

        if email is not None:
            if len(email) > 60:
                flash('O campo E-mail não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_clb')

        if len(email) < 4:
            flash('E-mail inválido.', category='error')
            return redirect(f'/edicao_clb/{clb_id}')

        if len(nome_civil) < 2:
            flash('Nome curto demais.', category='error')
            return redirect(f'/edicao_clb/{clb_id}')

        # VERIFICAÇÃO DE DUPLICAÇÃO NA BASE DADOS

        # Verifica se existe CPF cadastrado em outro cadastro!
        verifica_cpf = Colaborador.query.filter_by(cpf=cpf).first()
        if verifica_cpf and verifica_cpf.id != colaborador.id:
            flash(f'Falha ao atualizar o cadastro. CPF já cadastrado. ID correspondente: {colaborador.id}', category='error')
            return redirect('/colaboradores')

        # Verifica se existe se o E-mail está cadastrado em outro cadastro!
        verifica_email = Colaborador.query.filter_by(email=email).first()
        if verifica_email and verifica_email.id != colaborador.id:
            flash(f'Falha ao atualizar o cadastro. E-mail já cadastrado. ID correspondente: {colaborador.id}', category='error')
            return redirect('/colaboradores')

        colaborador = Colaborador.query.get(clb_id)
        colaborador.nome_civil = nome_civil
        colaborador.nome_social = nome_social
        colaborador.data_nascimento = data_nascimento
        colaborador.email = email
        colaborador.tipo_clb = tipo_clb
        colaborador.lotacao = lotacao
        colaborador.data_atualizacao = now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')
        colaborador.modificado_por = modificado_por

        db.session.commit()

        flash('O cadastro de foi atualizado com sucesso.', category='success')
        return redirect(f'/cadastro_clb/{clb_id}')

    return render_template('edicao_clb.html', campos_cad=campos_cad,
                                              colaborador=colaborador,
                                              data_criacao=data_criacao,
                                              data_atualizacao=data_atualizacao,
                                              titulo=titulo,
                                              )


@app.route('/edicao_psr/<int:psr_id>', methods=['GET', 'POST'])
@login_required
def edicao_psr(psr_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    pessoa = Pessoa.query.get(psr_id)

    if not pessoa:
        flash('Cadastro inexistente!', category='error')
        return redirect(url_for('pessoas'))

    titulo = 'Atualização PSR - CadPSR'
    titulo_body_1 = 'Atualização de Dados Cadastrais - PSR'
    titulo_body_2 = pessoa.nome_civil
    estado = ''

    if pessoa.data_criacao:
        data_criacao = carimbo_data(pessoa.data_criacao)
    else:
        data_criacao = ''
    if pessoa.data_atualizacao:
        data_atualizacao = carimbo_data(pessoa.data_atualizacao)
    else:
        data_atualizacao = ''

    if request.method == 'POST':

        pessoa = Pessoa.query.get(psr_id)

        nome_civil = request.form.get('nome_civil')
        nome_social = request.form.get('nome_social')
        if nome_civil is None or nome_civil == '':
            flash('É necessário informar o nome civil.', category='error')
            return redirect(url_for('novo_psr'))

        if nome_social is None or nome_social == '':
            nome_social = nome_civil

        rg = request.form.get('rg')
        titulo_eleitor = request.form.get('titulo_eleitor')
        cns = request.form.get('cns')

        nis = request.form.get('nis')
        certidao_nascimento = request.form.get('certidao_nascimento')
        crnm_rnm = request.form.get('crnm_rnm')

        # VALIDAÇÕES DE CAMPOS DE ENTRADA

        if nome_civil is not None:
            if len(nome_civil) > 60:
                flash('O campo Nome Civil não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if nome_social is not None:
            if len(nome_social) > 60:
                flash('O campo Nome Social não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('apelido') is not None:
            if len(request.form.get('apelido')) > 60:
                flash('O campo Apelido não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('email') is not None:
            if len(request.form.get('email')) > 60:
                flash('O campo E-mail não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('telefone') is not None:
            if len(request.form.get('telefone')) > 15:
                flash('O campo Telefone não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('celular') is not None:
            if len(request.form.get('celular')) > 15:
                flash('O campo Celular não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg') is not None:
            if len(request.form.get('rg')) > 16:
                flash('O campo RG não pode conter mais de 16 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg_emissao') is not None:
            if len(request.form.get('rg_emissao')) > 10:
                flash('O campo RG Emissão não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg_orgao_emissor') is not None:
            if len(request.form.get('rg_orgao_emissor')) > 60:
                flash('O campo RG Órgão Emissor não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_eleitor') is not None:
            if len(request.form.get('titulo_eleitor')) > 12:
                flash('O campo Título de Eleitor não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_zona') is not None:
            if len(request.form.get('titulo_zona')) > 6:
                flash('O campo Zona (Título de Eleitor) não pode conter mais de 6 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_secao') is not None:
            if len(request.form.get('titulo_secao')) > 6:
                flash('O campo Seção (Título de Eleitor) não pode conter mais de 6 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_emissao') is not None:
            if len(request.form.get('titulo_emissao')) > 10:
                flash('O campo Emissão (Título de Eleitor) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('cns') is not None:
            if len(request.form.get('cns')) > 15:
                flash('O campo CNS não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('nis') is not None:
            if len(request.form.get('nis')) > 12:
                flash('O campo NIS não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('certidao_nascimento') is not None:
            if len(request.form.get('certidao_nascimento')) > 32:
                flash('O campo Certidão Nascimento não pode conter mais de 32 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('naturalidade') is not None:
            if len(request.form.get('naturalidade')) > 60:
                flash('O campo Naturalidade não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('nacionalidade') is not None:
            if len(request.form.get('nacionalidade')) > 30:
                flash('O campo Nascionalidade não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_rnm') is not None:
            if len(request.form.get('crnm_rnm')) >  20:
                flash('O campo CRNM não pode conter mais de 20 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_filiacao_a') is not None:
            if len(request.form.get('crnm_filiacao_a')) > 60:
                flash('O campo Filiação (a) não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_filiacao_b') is not None:
            if len(request.form.get('crnm_filiacao_b')) > 60:
                flash('O campo Filiação (b) não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_validade') is not None:
            if len(request.form.get('crnm_validade')) > 10:
                flash('O Validade (CRNM) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_classificacao') is not None:
            if len(request.form.get('crnm_classificacao')) > 30:
                flash('O Classificação (CRNM) não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_domicilio') is not None:
            if len(request.form.get('crnm_domicilio')) > 100:
                flash('O campo Domicílio (CRNM) não pode conter mais de 100 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_emissao') is not None:
            if len(request.form.get('crnm_emissao')) > 10:
                flash('O Emissão (CRNM) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('questao_11') is not None:
            if len(request.form.get('questao_11')) > 12:
                flash('O campo referente à renda da Questão 11 não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('obs_psr') is not None:
            if len(request.form.get('obs_psr')) > 500:
                flash('O campo Observação não pode conter mais de 500 caracteres.', category='error')
                return redirect('/novo_psr')

        # VERIFICAÇÃO DE DUPLICAÇÃO DE DOCUMENTOS NA BASE DE DADOS

        doc = Pessoa.query.filter_by(rg=rg).first()  # Verifica RG
        if pessoa.rg is not None and pessoa.rg != '' and doc.rg is not None and doc.rg != '':
            if pessoa.rg != doc.rg:
                flash(
                    f'RG já cadastrado. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        # Verifica Título de Eleitor
        doc = Pessoa.query.filter_by(titulo_eleitor=titulo_eleitor).first()
        if pessoa.titulo_eleitor is not None and pessoa.titulo_eleitor != '' and doc.titulo_eleitor is not None and doc.titulo_eleitor != '':
            if pessoa.titulo_eleitor != doc.titulo_eleitor:
                flash(
                    f'Título de Eleitor já cadastrado. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        doc = Pessoa.query.filter_by(cns=cns).first()  # Verifica CNS

        if pessoa.cns:
            if pessoa.cns != doc.cns:
                flash(
                    f'CNS já cadastrado. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        doc = Pessoa.query.filter_by(nis=nis).first()  # Verifica NIS
        if pessoa.nis is not None and pessoa.nis != '' and doc.nis is not None and doc.nis != '':
            if pessoa.nis != doc.nis:
                flash(
                    f'NIS já cadastrado. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        # Verifica Certidão de Nascimento
        doc = Pessoa.query.filter_by(
            certidao_nascimento=certidao_nascimento).first()
        if pessoa.certidao_nascimento is not None and pessoa.certidao_nascimento != '' and doc.certidao_nascimento is not None and doc.certidao_nascimento != '':
            if pessoa.certidao_nascimento != doc.certidao_nascimento:
                flash(
                    f'Certidão de Nascimento já cadastrada. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        doc = Pessoa.query.filter_by(
            crnm_rnm=crnm_rnm).first()  # Verifica CRNM
        if pessoa.crnm_rnm is not None and pessoa.crnm_rnm != '' and doc.crnm_rnm is not None and doc.crnm_rnm != '':
            if pessoa.crnm_rnm != doc.crnm_rnm:
                flash(
                    f'CRNM de Nascimento já cadastrada. ID correspondente: {pessoa.id}.', category='error')
                return redirect(url_for('novo_psr'))

        if nome_social is None or nome_social == '':
            nome_social = request.form.get('nome_civil')

        pessoa = Pessoa.query.get(int(psr_id))

        pessoa.data_atualizacao = now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')
        pessoa.modificado_por = current_user.id
        pessoa.nome_civil = nome_civil
        pessoa.nome_social = nome_social
        pessoa.apelido = request.form.get('apelido')
        pessoa.data_nascimento = request.form.get('data_nascimento')
        pessoa.cidade_atual = request.form.get('cidade_atual')
        pessoa.entidade_referencia = request.form.get('entidade_referencia')
        pessoa.email = request.form.get('email')
        pessoa.telefone = request.form.get('telefone')
        pessoa.celular = request.form.get('celular')
        pessoa.etnia = request.form.get('etnia')
        pessoa.sexo = request.form.get('sexo')
        pessoa.orientacao_sexual = request.form.get('orientacao_sexual')
        pessoa.identidade_genero = request.form.get('identidade_genero')
        pessoa.rg = request.form.get('rg')
        pessoa.rg_uf = request.form.get('rg_uf')
        pessoa.rg_emissao = request.form.get('rg_emissao')
        pessoa.rg_orgao_emissor = request.form.get('rg_orgao_emissor')
        pessoa.titulo_eleitor = request.form.get('titulo_eleitor')
        pessoa.titulo_zona = request.form.get('titulo_zona')
        pessoa.titulo_secao = request.form.get('titulo_secao')
        pessoa.titulo_emissao = request.form.get('titulo_emissao')
        pessoa.cns = request.form.get('cns')
        pessoa.nis = request.form.get('nis')
        pessoa.certidao_nascimento = request.form.get('certidao_nascimento')
        pessoa.naturalidade = request.form.get('naturalidade')
        pessoa.nacionalidade = request.form.get('nacionalidade')
        pessoa.crnm_rnm = request.form.get('crnm_rnm')
        pessoa.crnm_filiacao_a = request.form.get('crnm_filiacao_a')
        pessoa.crnm_filiacao_b = request.form.get('crnm_filiacao_b')
        pessoa.crnm_validade = request.form.get('crnm_validade')
        pessoa.crnm_classificacao = request.form.get('crnm_classificacao')
        pessoa.crnm_domicilio = request.form.get('crnm_domicilio')
        pessoa.crnm_emissao = request.form.get('crnm_emissao')
        pessoa.questao_migracao = request.form.get('questao_migracao')
        pessoa.questao_1 = lista_para_str(request.form.getlist("questao_1"))
        pessoa.questao_2 = request.form.get('questao_2')
        pessoa.questao_3 = lista_para_str(request.form.getlist("questao_3"))
        pessoa.questao_4 = request.form.get('questao_4')
        pessoa.questao_5 = request.form.get('questao_5')
        pessoa.questao_6 = request.form.get('questao_6')
        pessoa.questao_7 = lista_para_str(request.form.getlist("questao_7"))
        pessoa.questao_8 = lista_para_str(request.form.getlist("questao_8"))
        pessoa.questao_9 = request.form.get('questao_9')
        pessoa.questao_10 = lista_para_str(request.form.getlist("questao_10"))
        pessoa.questao_11 = request.form.get('questao_11')
        pessoa.questao_12 = request.form.get('questao_12')
        pessoa.questao_13 = lista_para_str(request.form.getlist("questao_13"))
        pessoa.questao_14 = request.form.get('questao_14')
        pessoa.obs_psr = request.form.get('obs_psr')

        db.session.commit()
        flash(
            f'O cadastro de {pessoa.nome_civil} foi atualizado com sucesso!', category='success')
        return redirect(f'/cadastro_psr/{psr_id}')

    return render_template('/edicao_psr.html',
                           campos_cad=campos_cad,
                           colaborador=current_user,
                           data_atualizacao=data_atualizacao,
                           data_criacao=data_criacao,
                           estado=estado,
                           pessoa=pessoa,
                           questionario=questionario,
                           titulo=titulo,
                           titulo_body_1=titulo_body_1,
                           titulo_body_2=titulo_body_2
                           )


@app.route('/exclusao_clb/<clb_id>', methods=['POST'])
@login_required
def exclusao_clb(clb_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    colaborador = Colaborador.query.get(clb_id)

    if not colaborador:
        flash('Erro ao excluir cadastro: Colaborador não localizado.',
              category='error')
        return redirect(url_for('colaboradores'))

    if current_user.tipo_clb == colaborador.tipo_clb:
        flash('Você não tem permissão para excluir seu próprio cadastro.',
              category='error')
        return redirect(url_for('index'))

    if current_user.lotacao == 'GERENTE' and current_user.lotacao != colaborador.lotacao:
        flash('Você não tem permissão para alterar/desativar cadastros de Colaboradores de outras Entidades.', category='error')
        colaboradores = Colaborador.query.all()
        return render_template('colaboradores.html', colaboradores=colaboradores)

    db.session.delete(colaborador)
    db.session.commit()
    flash(
        f'O cadastro de {colaborador.nome_civil} foi excluído com sucesso.', category='success')
    return redirect('/colaboradores')


@app.route('/exclusao_psr/<psr_id>', methods=['POST'])
@login_required
def exclusao_psr(psr_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    pessoa = Pessoa.query.get(psr_id)

    if not pessoa:
        flash('Erro ao excluir cadastro: cadastro não localizado.', category='error')
        return redirect(url_for('pessoas'))

    db.session.delete(pessoa)
    db.session.commit()
    flash(
        f'O cadastro de {pessoa.nome_civil} foi excluído com sucesso.', category='success')

    return redirect('/pessoas')


@app.route('/novo_clb', methods=['GET', 'POST'])
@login_required
def novo_clb():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    titulo = 'Cadastro Colaborador - CadPSR'
    titulo_body_1 = 'Dados Cadastrais - Colaborador'
    titulo_body_2 = 'Novo Cadastro - Colaborador'
    estado = ''

    return render_template("novo_clb.html", campos_cad=campos_cad,
                                            colaborador=current_user,
                                            estado=estado,
                                            questionario=questionario,
                                            titulo=titulo,
                                            titulo_body_1=titulo_body_1,
                                            titulo_body_2=titulo_body_2
                                            )


@app.route('/novo_psr', methods=['GET', 'POST'])
@login_required
def novo_psr():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    titulo = 'Novo Cadastro PSR'
    titulo_body_1 = 'Dados Cadastrais - PSR'
    titulo_body_2 = 'Novo Cadastro - PSR'

    return render_template('novo_psr.html', campos_cad=campos_cad,
                                            questionario=questionario,
                                            titulo=titulo,
                                            titulo_body_1=titulo_body_1,
                                            titulo_body_2=titulo_body_2
                                            )


@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():

    if current_user.status == 'ATIVO':
        titulo = 'Perfil - Colaborador(a)'
        subtitulo = 'Alteração de Senha'

    if current_user.status == 'REDEF':
        titulo = 'Redefinição de Senha efetuada por Chefia'
        subtitulo = 'Por favor, altere sua senha (é obrigatório).'

    if current_user.status == 'INICIO':
        titulo = 'Primeiro Acesso'
        subtitulo = 'Boas-vindas. Este é seu primeiro acesso. É necessário alterar sua senha.'


    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        senha_nova = request.form.get('senha_nova')
        senha_confirmacao = request.form.get('senha_confirmacao')

        senha = current_user.senha

        if not check_password_hash(senha, senha_atual):
            flash('A senha atual não corresponde à senha armazenada.', category='error')
            return redirect('/perfil')


        elif senha_atual == senha_nova:
            flash('A nova senha precisa ser diferente da senha atual.', category='error')
            return redirect('/perfil')

        if senha_nova != senha_confirmacao:
            flash('Os campos de *Nova Senha e *Confirmação de Senha não se correspondem.', category='error')
            return redirect('/perfil')

        if len(senha_nova) < 10:
            flash('A senha precisa conter no mínimo 10 dígitos.', category='error')
            return redirect('/perfil')

        if len(senha_nova) > 64:
            flash('A senha não pode conter mais de 64 caracteres.', category='error')
            return redirect('/perfil')

        senha_hash = generate_password_hash(senha_nova)
        current_user.senha = senha_hash
        if current_user.status == 'REDEF' or current_user.status == 'INICIO':
            current_user.status = 'ATIVO'
            mensagem = 'Senha alterada com sucesso. Agora você pode acessar o sistema.'
        else:
            mensagem = 'Senha alterada com sucesso.'
        db.session.commit()
        del senha_atual
        del senha_nova
        del senha_hash

        flash(mensagem, category='success')
        return redirect('/index')

    return render_template('perfil.html', campos_cad=campos_cad,
                                          colaborador=current_user,
                                          subtitulo=subtitulo,
                                          titulo=titulo
                                          )


@app.route('/persistencia_psr', methods=['POST'])
@login_required
def persistencia_psr():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    if request.method == 'POST':
        if not request.form.get('nome_civil'):
            flash('É necessário informar o nome civil.', category='error')
            return redirect(url_for('novo_psr'))

        nome_civil = request.form.get('nome_civil')
        nome_social = request.form.get('nome_social')
        if request.form.get('nome_social') is None:
            nome_social = nome_civil

        cpf = request.form.get('cpf')
        rg = request.form.get('rg')
        titulo_eleitor = request.form.get('titulo_eleitor')
        cns = request.form.get('cns')
        nis = request.form.get('nis')
        certidao_nascimento = request.form.get('certidao_nascimento')
        crnm_rnm = request.form.get('crnm_rnm')

        # VALIDAÇÕES DOS CAMPOS DE ENTRADA

        if nome_civil is not None:
            if len(nome_civil) > 60:
                flash('O campo Nome Civil não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if nome_social is not None:
            if len(nome_social) > 60:
                flash('O campo Nome Social não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('apelido') is not None:
            if len(request.form.get('apelido')) > 60:
                flash('O campo Apelido não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('email') is not None:
            if len(request.form.get('email')) > 60:
                flash('O campo E-mail não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('telefone') is not None:
            if len(request.form.get('telefone')) > 15:
                flash('O campo Telefone não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('celular') is not None:
            if len(request.form.get('celular')) > 15:
                flash('O campo Celular não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg') is not None:
            if len(request.form.get('rg')) > 16:
                flash('O campo RG não pode conter mais de 16 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg_emissao') is not None:
            if len(request.form.get('rg_emissao')) > 10:
                flash('O campo RG Emissão não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('rg_orgao_emissor') is not None:
            if len(request.form.get('rg_orgao_emissor')) > 60:
                flash('O campo RG Órgão Emissor não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_eleitor') is not None:
            if len(request.form.get('titulo_eleitor')) > 12:
                flash('O campo Título de Eleitor não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_zona') is not None:
            if len(request.form.get('titulo_zona')) > 6:
                flash('O campo Zona (Título de Eleitor) não pode conter mais de 6 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_secao') is not None:
            if len(request.form.get('titulo_secao')) > 6:
                flash('O campo Seção (Título de Eleitor) não pode conter mais de 6 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('titulo_emissao') is not None:
            if len(request.form.get('titulo_emissao')) > 10:
                flash('O campo Emissão (Título de Eleitor) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('cns') is not None:
            if len(request.form.get('cns')) > 15:
                flash('O campo CNS não pode conter mais de 15 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('nis') is not None:
            if len(request.form.get('nis')) > 12:
                flash('O campo NIS não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('certidao_nascimento') is not None:
            if len(request.form.get('certidao_nascimento')) > 32:
                flash('O campo Certidão Nascimento não pode conter mais de 32 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('naturalidade') is not None:
            if len(request.form.get('naturalidade')) > 60:
                flash('O campo Naturalidade não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('nacionalidade') is not None:
            if len(request.form.get('nacionalidade')) > 30:
                flash('O campo Nascionalidade não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_rnm') is not None:
            if len(request.form.get('crnm_rnm')) >  20:
                flash('O campo CRNM não pode conter mais de 20 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_filiacao_a') is not None:
            if len(request.form.get('crnm_filiacao_a')) > 60:
                flash('O campo Filiação (a) não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_filiacao_b') is not None:
            if len(request.form.get('crnm_filiacao_b')) > 60:
                flash('O campo Filiação (b) não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_validade') is not None:
            if len(request.form.get('crnm_validade')) > 10:
                flash('O Validade (CRNM) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_classificacao') is not None:
            if len(request.form.get('crnm_classificacao')) > 30:
                flash('O Classificação (CRNM) não pode conter mais de 30 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_domicilio') is not None:
            if len(request.form.get('crnm_domicilio')) > 100:
                flash('O campo Domicílio (CRNM) não pode conter mais de 100 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('crnm_emissao') is not None:
            if len(request.form.get('crnm_emissao')) > 10:
                flash('O Emissão (CRNM) não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('questao_11') is not None:
            if len(request.form.get('questao_11')) > 12:
                flash('O campo referente à renda da Questão 11 não pode conter mais de 12 caracteres.', category='error')
                return redirect('/novo_psr')

        if request.form.get('obs_psr') is not None:
            if len(request.form.get('obs_psr')) > 500:
                flash('O campo Observação não pode conter mais de 500 caracteres.', category='error')
                return redirect('/novo_psr')


        # VERIFICAÇÃO DE DUPLICAÇÃO DE DOCUMENTOS CADASTRADOS NA BASE DE DADOS

        pessoa = Pessoa.query.filter_by(cpf=cpf).first()  # Verifica CPF
        if pessoa:
            flash(f'CPF já cadastrado. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        pessoa = Pessoa.query.filter_by(rg=rg).first()  # Verifica RG
        if pessoa and pessoa.rg != '':
            flash(f'RG já cadastrado. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        pessoa = Pessoa.query.filter_by(
            titulo_eleitor=titulo_eleitor).first()  # Verifica Título de Eleitor
        if pessoa and pessoa.titulo_eleitor != '':
            flash(f'Título de Eleitor já cadastrado. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        pessoa = Pessoa.query.filter_by(cns=cns).first()  # Verifica CNS
        if pessoa and pessoa.cns != '':
            flash(f'CNS já cadastrado. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        pessoa = Pessoa.query.filter_by(nis=nis).first()  # Verifica NIS
        if pessoa and pessoa.nis != '':
            flash(f'NIS já cadastrado. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        # Verifica Certidão de Nascimento
        pessoa = Pessoa.query.filter_by(
            certidao_nascimento=certidao_nascimento).first()
        if pessoa and pessoa.certidao_nascimento != '':
            flash(f'Certidão de Nascimento já cadastrada. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        pessoa = Pessoa.query.filter_by(
            crnm_rnm=crnm_rnm).first()  # Verifica CRNM
        if pessoa and pessoa.crnm_rnm:
            flash(f'CRNM de Nascimento já cadastrada. ID correspondente: {pessoa.id}.', category='error')
            return redirect(url_for('novo_psr'))

        if not cpf.isdigit():
            flash('CPF inválido. Digite apenas números.', category='error')
            return redirect(url_for('novo_psr'))

        elif len(cpf) != 11:
            flash('O CPF deve conter exatos 11 dígitos.', category='error')
            return redirect(url_for('novo_psr'))




        pessoa = Pessoa(status='ATIVO',
                        data_criacao=now(
                            'America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss'),
                        criado_por=current_user.id,
                        nome_civil=nome_civil,
                        nome_social=nome_social,
                        apelido=request.form.get('apelido'),
                        cpf=cpf,
                        data_nascimento=request.form.get('data_nascimento'),
                        cidade_atual=request.form.get('cidade_atual'),
                        entidade_referencia=request.form.get('entidade_referencia'),
                        email=request.form.get('email'),
                        telefone=request.form.get('telefone'),
                        celular=request.form.get('celular'),
                        etnia=request.form.get('etnia'),
                        sexo=request.form.get('sexo'),
                        orientacao_sexual=request.form.get('orientacao_sexual'),
                        identidade_genero=request.form.get('identidade_genero'),
                        rg=request.form.get('rg'),
                        rg_uf=request.form.get('rg_uf'),
                        rg_emissao=request.form.get('rg_emissao'),
                        rg_orgao_emissor=request.form.get('rg_orgao_emissor'),
                        titulo_eleitor=request.form.get('titulo_eleitor'),
                        titulo_zona=request.form.get('titulo_zona'),
                        titulo_secao=request.form.get('titulo_secao'),
                        titulo_emissao=request.form.get('titulo_emissao'),
                        cns=request.form.get('cns'),
                        nis=request.form.get('nis'),
                        certidao_nascimento=request.form.get('certidao_nascimento'),
                        naturalidade=request.form.get('naturalidade'),
                        nacionalidade=request.form.get('nacionalidade'),
                        crnm_rnm=request.form.get('crnm_rnm'),
                        crnm_filiacao_a=request.form.get('crnm_filiacao_a'),
                        crnm_filiacao_b=request.form.get('crnm_filiacao_b'),
                        crnm_validade=request.form.get('crnm_validade'),
                        crnm_classificacao=request.form.get('crnm_classificacao'),
                        crnm_domicilio=request.form.get('crnm_domicilio'),
                        crnm_emissao=request.form.get('crnm_emissao'),
                        questao_migracao=request.form.get('questao_migracao'),
                        questao_1=lista_para_str(request.form.getlist("questao_1")),
                        questao_2=request.form.get('questao_2'),
                        questao_3=lista_para_str(request.form.getlist("questao_3")),
                        questao_4=request.form.get('questao_4'),
                        questao_5=request.form.get('questao_5'),
                        questao_6=request.form.get('questao_6'),
                        questao_7=lista_para_str(request.form.getlist("questao_7")),
                        questao_8=lista_para_str(request.form.getlist("questao_8")),
                        questao_9=request.form.get('questao_9'),
                        questao_10=lista_para_str(request.form.getlist("questao_10")),
                        questao_11=request.form.get('questao_11'),
                        questao_12=request.form.get('questao_12'),
                        questao_13=lista_para_str(request.form.getlist("questao_13")),
                        questao_14=request.form.get('questao_14'),
                        obs_psr=request.form.get('obs_psr')
                        )
        db.session.add(pessoa)
        db.session.commit()
        pessoa = Pessoa.query.filter_by(cpf=cpf).first()
        flash(f'{pessoa.nome_civil} foi cadastrado(a) com sucesso!', category='success')
        return redirect(f'/cadastro_psr/{pessoa.id}')

    return redirect(f'cadastro_psr/{pessoa.id}')


@app.route('/persistencia_clb', methods=['POST'])
@login_required
def persistencia_clb():
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    if request.method == 'POST':

        nome_civil = request.form.get('nome_civil')
        nome_social = request.form.get('nome_social')
        if nome_social is None or nome_social == '':
            nome_social = request.form.get('nome_civil')
        cpf = request.form.get('cpf')
        data_nascimento = request.form.get('data_nascimento')
        email = request.form.get('email')
        tipo_clb = request.form.get('tipo_clb')
        lotacao = request.form.get('lotacao')
        data_criacao = now('America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')
        criado_por = current_user.id

        # VERIFICAÇÃO DE ENTRADA DE DADOS

        if nome_civil is not None:
            if len(nome_civil) > 60:
                flash('O campo Nome Civil não pode conter mais de  caracteres.', category='error')
                return redirect('/novo_clb')

        if nome_social is not None:
            if len(nome_social) > 60:
                flash('O campo Nome Social não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_clb')

        if cpf is not None:
            if len(cpf) > 11:
                flash('O campo CPF não pode conter mais de  caracteres.', category='error')
                return redirect('/novo_clb')

        if data_nascimento is not None:
            if len(data_nascimento) > 10:
                flash('O campo "Data de Nascimento" não pode conter mais de 10 caracteres.', category='error')
                return redirect('/novo_clb')

        if email is not None:
            if len(email) > 60:
                flash('O campo E-mail não pode conter mais de 60 caracteres.', category='error')
                return redirect('/novo_clb')

        # VERIFICAÇÃO DE DUPLICAÇÃO NA BASE DE DADOS

        verifica_cpf = Colaborador.query.filter_by(cpf=cpf).first()  # Verifica e-mail
        if verifica_cpf:
            flash(f'CPF já cadastrado. ID correspondente: {verifica_cpf.id}!', category='error')
            return redirect('/novo_clb')

        verifica_email = Colaborador.query.filter_by(email=email).first()  # Verifica e-mail
        if verifica_email:
            flash(f'E-mail já cadastrado. ID correspondente: {verifica_email.id}!', category='error')
            return redirect('/novo_clb')
        if not cpf.isdigit():
            flash('CPF inválido. Digite apenas números.', category='error')
            return redirect('/novo_clb')
        if len(cpf) != 11:
            flash('O CPF deve conter exatos 11 dígitos.', category='error')
            return redirect('/novo_clb')
        if len(nome_civil) < 2:
            flash('Nome curto demais.', category='error')
            return redirect('/novo_clb')



        colaborador = Colaborador(status='INICIO',
                                  nome_civil=nome_civil,
                                  nome_social=nome_social,
                                  cpf=cpf,
                                  data_nascimento=data_nascimento,
                                  email=email,
                                  tipo_clb=tipo_clb,
                                  lotacao=lotacao,
                                  data_criacao=data_criacao,
                                  criado_por=criado_por)
        senha_gerada = token_hex(7)
        # Gera hash da senha e o atribui ao campo senha
        colaborador.seta_senha_hash(senha_gerada)
        db.session.add(colaborador)
        db.session.commit()
        flash(f'Cadastro de {colaborador.nome_civil} efetuado com sucesso. Senha temporária: {senha_gerada}', category='success')
        del senha_gerada
        return redirect(f'cadastro_clb/{colaborador.id}')

    return redirect(f'cadastro_psr/{colaborador.id}')


@app.route('/status_clb/<int:clb_id>', methods=['POST'])
@login_required
def status_clb(clb_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')
    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')

    colaborador = Colaborador.query.get(clb_id)
    if Colaborador:
        if colaborador.status == 'ATIVO' or colaborador.status == 'REDEF' or colaborador.status == 'INICIO':
            senha_gerada = token_hex(64)
            colaborador.seta_senha_hash(senha_gerada)
            colaborador.status = 'INATIVO'
            colaborador.data_atualizacao = now(
                'America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')

            flash('Cadastro INATIVADO com sucesso.', category='success')
        else:
            colaborador.status = 'REDEF'
            senha_gerada = token_hex(7)
            colaborador.seta_senha_hash(senha_gerada)
            colaborador.data_atualizacao = now(
                'America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')
            flash(
                f'Cadastro ATIVADO com sucesso. Senha temporária: {senha_gerada}', category='success')

        db.session.commit()
    else:
        flash('Cadastro não localizado.', category='error')

    return redirect(f'/cadastro_clb/{colaborador.id}')


@app.route('/status_psr/<int:psr_id>', methods=['POST'])
@login_required
def status_psr(psr_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    pessoa = Pessoa.query.get(psr_id)
    if Pessoa:
        if pessoa.status == 'ATIVO':
            pessoa.status = 'INATIVO'
            flash('Cadastro INATIVADO com sucesso.', category='success')
        else:
            pessoa.status = 'ATIVO'
            flash('Cadastro ATIVADO com sucesso.', category='success')

        db.session.commit()
    else:
        flash('Cadastro não localizado.', category='error')
        return redirect('/pessoas')

    return redirect(f'/cadastro_psr/{psr_id}')


@app.route('/redefinicao_senha/<clb_id>', methods=['POST'])
@login_required
def redefinicao_senha(clb_id):
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('perfil')

    if current_user.tipo_clb == 'COLABORADOR(A)':
        flash('Acesso não autorizado!')
        return redirect('/index.html')
    if current_user.status == 'INICIO' or current_user.status == 'REDEF':
        flash('Para acessar outras áreas do sistema, você precisa alterar sua senha!', category='error')
        return redirect('/index.html')

    colaborador = Colaborador.query.get(clb_id)
    if request.method == 'POST':
        if not colaborador:
            flash('Erro! Colaborador não encontrado(a). Contate o Admin.',
                  category='error')
            return redirect('/colaboradores')

        if current_user.tipo_clb != 'GESTOR' and current_user.lotacao != colaborador.lotacao:
            flash('Você não tem permissão para alterar o cadastro de colaboradores de outras Entidades!', category='error')
            return redirect('/index.html')
        if current_user.id == colaborador.id:
            flash('Acesso não autorizado: para alterar sua senha utilize a página de Perfil!', category='error')
            return redirect('/index.html')
        if colaborador.status == 'INATIVO':
            flash(f'Não foi possível redefirnir a senha. STATUS INATIVO.', category='error')
            return redirect(f'/cadastro_clb/{clb_id}')
        if colaborador.status == 'REDEF' and current_user.tipo_clb != 'GESTOR':
            flash(f'Senha já foi redefinida. Aguarde o(a) Colaborador(a) acessar o sistema ou contate o Admin.', category='error')
            return redirect(f'/cadastro_clb/{clb_id}')
        if colaborador.status == 'INICIO' and current_user.tipo_clb != 'GESTOR':
            flash(f'Não foi possível redefinir a senha. Colaborador(a) ainda não efetuou o primeiro acesso.', category='error')
            return redirect(f'/cadastro_clb/{clb_id}')

        senha_gerada = token_hex(7)
        colaborador.seta_senha_hash(senha_gerada)
        if colaborador.status != 'INICIO':
            colaborador.status = 'REDEF'
            colaborador.data_atualizacao = now(
                'America/Sao_Paulo').format('DD-MM-YYYY-HH-mm-ss')
        db.session.commit()
        flash(
            f'A senha de {colaborador.nome_social} foi redefinida com sucesso. Senha temporária: {senha_gerada}', category='success')
        del senha_gerada

    return redirect(f'/cadastro_clb/{clb_id}')
